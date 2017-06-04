from __future__ import unicode_literals, division, absolute_import, print_function
import click
import hashlib
import os
from asn1crypto.util import timezone
from datetime import datetime, timedelta

from asn1crypto import cms, algos, x509, ocsp
from base64 import b64decode, b64encode
from certbuilder import pem_armor_certificate
from certidude import authority, push, config
from certidude.firewall import whitelist_subnets
from oscrypto import keys, asymmetric, symmetric
from oscrypto.errors import SignatureError

class OCSPResource(object):
    def on_post(self, req, resp):
        fh = open(config.AUTHORITY_CERTIFICATE_PATH)
        server_certificate = asymmetric.load_certificate(fh.read())
        fh.close()

        ocsp_req = ocsp.OCSPRequest.load(req.stream.read())
        print(ocsp_req["tbs_request"].native)

        now = datetime.now(timezone.utc)
        response_extensions = []

        for ext in ocsp_req["tbs_request"]["request_extensions"]:
            if ext["extn_id"] == "nonce":
                response_extensions.append(
                    ocsp.ResponseDataExtension({
                        'extn_id': "nonce",
                        'critical': False,
                        'extn_value': ext["extn_value"]
                    })
                )

        responses = []
        for item in ocsp_req["tbs_request"]["request_list"]:
            serial = item["req_cert"]["serial_number"].native

            try:
                link_target = os.readlink(os.path.join(config.SIGNED_BY_SERIAL_DIR, "%x.pem" % serial))
                assert link_target.startswith("../")
                assert link_target.endswith(".pem")
                path, buf, cert = authority.get_signed(link_target[3:-4])
                if serial != cert.serial:
                    raise EnvironmentError("integrity check failed")
                status = ocsp.CertStatus(name='good', value=None)
            except EnvironmentError:
                try:
                    path, buf, cert, revoked = authority.get_revoked(serial)
                    status = ocsp.CertStatus(
                        name='revoked',
                        value={
                            'revocation_time': revoked,
                            'revocation_reason': "key_compromise",
                        })
                except EnvironmentError:
                    status = ocsp.CertStatus(name="unknown", value=None)

            responses.append({
                'cert_id': {
                    'hash_algorithm': {
                        'algorithm': "sha1"
                    },
                    'issuer_name_hash': server_certificate.asn1.subject.sha1,
                    'issuer_key_hash': server_certificate.public_key.asn1.sha1,
                    'serial_number': serial,
                },
                'cert_status': status,
                'this_update': now,
                'single_extensions': []
            })

        response_data = ocsp.ResponseData({
            'responder_id': ocsp.ResponderId(name='by_key', value=server_certificate.public_key.asn1.sha1),
            'produced_at': now,
            'responses': responses,
            'response_extensions': response_extensions
        })

        resp.body = ocsp.OCSPResponse({
            'response_status': "successful",
            'response_bytes': {
                'response_type': 'basic_ocsp_response',
                'response': {
                    'tbs_response_data': response_data,
                    'signature_algorithm': {'algorithm': "sha1_rsa"},
                    'signature': b64decode(authority.signer_exec("sign-pkcs7", b64encode(response_data.dump()))),
                    'certs': [server_certificate.asn1]
                }
            }
        }).dump()

