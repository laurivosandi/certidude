import click
import hashlib
import os
from asn1crypto import cms, algos, x509
from asn1crypto.core import ObjectIdentifier, SetOf, PrintableString
from base64 import b64decode, b64encode
from certbuilder import pem_armor_certificate
from certidude import authority, push, config
from certidude.firewall import whitelist_subnets
from oscrypto import keys, asymmetric, symmetric
from oscrypto.errors import SignatureError

# Monkey patch asn1crypto

class SetOfPrintableString(SetOf):
    _child_spec = PrintableString

cms.CMSAttributeType._map['2.16.840.1.113733.1.9.2'] = "message_type"
cms.CMSAttributeType._map['2.16.840.1.113733.1.9.3'] = "pki_status"
cms.CMSAttributeType._map['2.16.840.1.113733.1.9.4'] = "fail_info"
cms.CMSAttributeType._map['2.16.840.1.113733.1.9.5'] = "sender_nonce"
cms.CMSAttributeType._map['2.16.840.1.113733.1.9.6'] = "recipient_nonce"
cms.CMSAttributeType._map['2.16.840.1.113733.1.9.7'] = "trans_id"

cms.CMSAttribute._oid_specs['message_type'] = SetOfPrintableString
cms.CMSAttribute._oid_specs['pki_status'] = SetOfPrintableString
cms.CMSAttribute._oid_specs['fail_info'] = SetOfPrintableString
cms.CMSAttribute._oid_specs['sender_nonce'] = cms.SetOfOctetString
cms.CMSAttribute._oid_specs['recipient_nonce'] = cms.SetOfOctetString
cms.CMSAttribute._oid_specs['trans_id'] = SetOfPrintableString

class SCEPError(Exception): code = 25 # system failure
class SCEPBadAlg(SCEPError): code = 0
class SCEPBadMessageCheck(SCEPError): code = 1
class SCEPBadRequest(SCEPError): code = 2
class SCEPBadTime(SCEPError): code = 3
class SCEPBadCertId(SCEPError): code = 4

class SCEPResource(object):
    @whitelist_subnets(config.SCEP_SUBNETS)
    def on_get(self, req, resp):
        operation = req.get_param("operation")
        if operation.lower() == "getcacert":
            resp.body = keys.parse_certificate(authority.certificate_buf).dump()
            resp.append_header("Content-Type", "application/x-x509-ca-cert")
            return

        # If we bump into exceptions later
        encrypted_container = b""
        attr_list = [
            cms.CMSAttribute({
                'type': "message_type",
                'values': ["3"]
            }),
            cms.CMSAttribute({
                'type': "pki_status",
                'values': ["2"] # rejected
            })
        ]

        try:
            info = cms.ContentInfo.load(b64decode(req.get_param("message", required=True)))

            ###############################################
            ### Verify signature of the outer container ###
            ###############################################

            signed_envelope = info['content']
            encap_content_info = signed_envelope['encap_content_info']
            encap_content = encap_content_info['content']

            # TODO: try except
            current_certificate, = signed_envelope["certificates"]
            signer, = signed_envelope["signer_infos"]

            # TODO: compare cert to current one if we are renewing

            assert signer["digest_algorithm"]["algorithm"].native == "md5"
            assert signer["signature_algorithm"]["algorithm"].native == "rsassa_pkcs1v15"
            message_digest = None
            transaction_id = None
            sender_nonce = None

            for attr in signer["signed_attrs"]:
                if attr["type"].native == "sender_nonce":
                    sender_nonce, = attr["values"]
                elif attr["type"].native == "trans_id":
                    transaction_id, = attr["values"]
                elif attr["type"].native == "message_digest":
                    message_digest, = attr["values"]
                    if hashlib.md5(encap_content.native).digest() != message_digest.native:
                        raise SCEPBadMessageCheck()

            assert message_digest
            msg = signer["signed_attrs"].dump(force=True)
            assert msg[0] == 160

            # Verify signature
            try:
                asymmetric.rsa_pkcs1v15_verify(
                    asymmetric.load_certificate(current_certificate.dump()),
                    signer["signature"].native,
                    b"\x31" + msg[1:], # wtf?!
                    "md5")
            except SignatureError:
                raise SCEPBadMessageCheck()

            ###############################
            ### Decrypt inner container ###
            ###############################

            info = cms.ContentInfo.load(encap_content.native)
            encrypted_envelope = info['content']
            encrypted_content_info = encrypted_envelope['encrypted_content_info']
            iv = encrypted_content_info['content_encryption_algorithm']['parameters'].native

            if encrypted_content_info['content_encryption_algorithm']["algorithm"].native != "des":
                raise SCEPBadAlgo()

            encrypted_content = encrypted_content_info['encrypted_content'].native
            recipient, = encrypted_envelope['recipient_infos']

            if recipient.native["rid"]["serial_number"] != authority.certificate.serial_number:
                raise SCEPBadCertId()

            # Since CA private key is not directly readable here, we'll redirect it to signer socket
            key = asymmetric.rsa_pkcs1v15_decrypt(
                authority.private_key,
                recipient.native["encrypted_key"])
            if len(key) == 8: key = key * 3 # Convert DES to 3DES
            buf = symmetric.tripledes_cbc_pkcs5_decrypt(key, encrypted_content, iv)
            _, _, common_name = authority.store_request(buf, overwrite=True)
            cert, buf = authority.sign(common_name, overwrite=True)
            signed_certificate = asymmetric.load_certificate(buf)
            content = signed_certificate.asn1.dump()

        except SCEPError as e:
            attr_list.append(cms.CMSAttribute({
                'type': "fail_info",
                'values': ["%d" % e.code]
            }))
        else:

            ##################################
            ### Degenerate inner container ###
            ##################################

            degenerate = cms.ContentInfo({
                'content_type': "signed_data",
                'content': cms.SignedData({
                    'version': "v1",
                    'certificates': [signed_certificate.asn1],
                    'digest_algorithms': [cms.DigestAlgorithm({
                        'algorithm': "md5"
                    })],
                    'encap_content_info': {
                        'content_type': "data",
                        'content':  cms.ContentInfo({
                            'content_type': "signed_data",
                            'content': None
                        }).dump()
                    },
                    'signer_infos': []
                })
            })


            ################################
            ### Encrypt middle container ###
            ################################

            key = os.urandom(8)
            iv, encrypted_content = symmetric.des_cbc_pkcs5_encrypt(key, degenerate.dump(), os.urandom(8))
            assert degenerate.dump() == symmetric.tripledes_cbc_pkcs5_decrypt(key*3, encrypted_content, iv)

            ri = cms.RecipientInfo({
                'ktri': cms.KeyTransRecipientInfo({
                    'version': "v0",
                    'rid': cms.RecipientIdentifier({
                        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                            'issuer': current_certificate.chosen["tbs_certificate"]["issuer"],
                            'serial_number': current_certificate.chosen["tbs_certificate"]["serial_number"],
                        }),
                    }),
                    'key_encryption_algorithm': {
                        'algorithm': "rsa"
                    },
                    'encrypted_key': asymmetric.rsa_pkcs1v15_encrypt(
                        asymmetric.load_certificate(current_certificate.chosen.dump()), key)
                })
            })

            encrypted_container = cms.ContentInfo({
                'content_type': "enveloped_data",
                'content': cms.EnvelopedData({
                    'version': "v1",
                    'recipient_infos': [ri],
                    'encrypted_content_info': {
                        'content_type': "data",
                        'content_encryption_algorithm': {
                            'algorithm': "des",
                            'parameters': iv
                        },
                        'encrypted_content': encrypted_content
                    }
                })
            }).dump()

            attr_list = [
                cms.CMSAttribute({
                    'type': "message_digest",
                    'values': [hashlib.sha1(encrypted_container).digest()]
                }),
                cms.CMSAttribute({
                    'type': "message_type",
                    'values': ["3"]
                }),
                cms.CMSAttribute({
                    'type': "pki_status",
                    'values': ["0"] # ok
                })
            ]
        finally:

            ##############################
            ### Signed outer container ###
            ##############################

            attrs = cms.CMSAttributes(attr_list + [
                cms.CMSAttribute({
                    'type': "recipient_nonce",
                    'values': [sender_nonce]
                }),
                cms.CMSAttribute({
                    'type': "trans_id",
                    'values': [transaction_id]
                })
            ])

            signer = cms.SignerInfo({
                "signed_attrs": attrs,
                'version': "v1",
                'sid': cms.SignerIdentifier({
                    'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                        'issuer': authority.certificate.issuer,
                        'serial_number': authority.certificate.serial_number,
                    }),
                }),
                'digest_algorithm': algos.DigestAlgorithm({'algorithm': "sha1"}),
                'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': "rsassa_pkcs1v15"}),
                'signature': asymmetric.rsa_pkcs1v15_sign(
                    authority.private_key,
                    b"\x31" + attrs.dump()[1:],
                    "sha1"
                )
            })

            resp.append_header("Content-Type", "application/x-pki-message")
            resp.body = cms.ContentInfo({
                'content_type': "signed_data",
                'content': cms.SignedData({
                    'version': "v1",
                    'certificates': [authority.certificate],
                    'digest_algorithms': [cms.DigestAlgorithm({
                        'algorithm': "sha1"
                    })],
                    'encap_content_info': {
                        'content_type': "data",
                        'content': encrypted_container
                    },
                    'signer_infos': [signer]
                })
            }).dump()
