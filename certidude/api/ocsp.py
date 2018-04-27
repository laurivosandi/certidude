import falcon
import logging
import os
from asn1crypto.util import timezone
from asn1crypto import ocsp
from base64 import b64decode
from certidude import config
from datetime import datetime
from oscrypto import asymmetric
from .utils import AuthorityHandler
from .utils.firewall import whitelist_subnets

logger = logging.getLogger(__name__)

class OCSPResource(AuthorityHandler):
    @whitelist_subnets(config.OCSP_SUBNETS)
    def __call__(self, req, resp):
        try:
            if req.method == "GET":
                _, _, _, tail = req.path.split("/", 3)
                body = b64decode(tail)
            elif req.method == "POST":
                body = req.stream.read(req.content_length or 0)
            else:
                raise falcon.HTTPMethodNotAllowed()
            ocsp_req = ocsp.OCSPRequest.load(body)
        except ValueError:
            raise falcon.HTTPBadRequest()

        fh = open(config.AUTHORITY_CERTIFICATE_PATH, "rb") # TODO: import from authority
        server_certificate = asymmetric.load_certificate(fh.read())
        fh.close()

        now = datetime.now(timezone.utc)
        response_extensions = []

        try:
            for ext in ocsp_req["tbs_request"]["request_extensions"]:
                if ext["extn_id"].native == "nonce":
                    response_extensions.append(
                        ocsp.ResponseDataExtension({
                            'extn_id': "nonce",
                            'critical': False,
                            'extn_value': ext["extn_value"]
                        })
                    )
        except ValueError: # https://github.com/wbond/asn1crypto/issues/56
            pass

        responses = []
        for item in ocsp_req["tbs_request"]["request_list"]:
            serial = item["req_cert"]["serial_number"].native
            assert serial > 0, "Serial number correctness check failed"

            try:
                link_target = os.readlink(os.path.join(config.SIGNED_BY_SERIAL_DIR, "%040x.pem" % serial))
                assert link_target.startswith("../")
                assert link_target.endswith(".pem")
                path, buf, cert, signed, expires = self.authority.get_signed(link_target[3:-4])
                if serial != cert.serial_number:
                    logger.error("Certificate store integrity check failed, %s refers to certificate with serial %040x", link_target, cert.serial_number)
                    raise EnvironmentError("Integrity check failed")
                logger.debug("OCSP responder queried from %s for %s with serial %040x, returned status 'good'",
                    req.context.get("remote_addr"), cert.subject.native["common_name"], serial)
                status = ocsp.CertStatus(name='good', value=None)
            except EnvironmentError:
                try:
                    path, buf, cert, signed, expires, revoked, reason = self.authority.get_revoked(serial)
                    logger.debug("OCSP responder queried from %s for %s with serial %040x, returned status 'revoked' due to %s",
                        req.context.get("remote_addr"), cert.subject.native["common_name"], serial, reason)
                    status = ocsp.CertStatus(
                        name='revoked',
                        value={
                            'revocation_time': revoked,
                            'revocation_reason': reason,
                        })
                except EnvironmentError:
                    logger.info("OCSP responder queried for unknown serial %040x from %s", serial, req.context.get("remote_addr"))
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
                'response_type': "basic_ocsp_response",
                'response': {
                    'tbs_response_data': response_data,
                    'certs': [server_certificate.asn1],
                    'signature_algorithm': {'algorithm': "sha1_ecdsa" if self.authority.public_key.algorithm == "ec" else "sha1_rsa" },
                    'signature': (asymmetric.ecdsa_sign if self.authority.public_key.algorithm == "ec" else asymmetric.rsa_pkcs1v15_sign)(
                        self.authority.private_key,
                        response_data.dump(),
                        "sha1"
                    )
                }
            }
        }).dump()

