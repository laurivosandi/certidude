
import click
import falcon
import json
import logging
from certidude import const, config
from certidude.authority import export_crl, list_revoked
from certidude.firewall import whitelist_subnets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

logger = logging.getLogger(__name__)

class RevocationListResource(object):
    @whitelist_subnets(config.CRL_SUBNETS)
    def on_get(self, req, resp):
        # Primarily offer DER encoded CRL as per RFC5280
        # This is also what StrongSwan expects
        if req.client_accepts("application/x-pkcs7-crl"):
            resp.set_header("Content-Type", "application/x-pkcs7-crl")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s.crl" % const.HOSTNAME).encode("ascii"))
            # Convert PEM to DER
            logger.debug(u"Serving revocation list to %s in DER format", req.context.get("remote_addr"))
            resp.body = x509.load_pem_x509_crl(export_crl(),
                default_backend()).public_bytes(Encoding.DER)
        elif req.client_accepts("application/x-pem-file"):
            if req.get_param_as_bool("wait"):
                url = config.LONG_POLL_SUBSCRIBE % "crl"
                resp.status = falcon.HTTP_SEE_OTHER
                resp.set_header("Location", url.encode("ascii"))
                logger.debug(u"Redirecting to CRL request to %s", url)
                resp.body = "Redirecting to %s" % url
            else:
                resp.set_header("Content-Type", "application/x-pem-file")
                resp.append_header(
                    "Content-Disposition",
                    ("attachment; filename=%s-crl.pem" % const.HOSTNAME).encode("ascii"))
                logger.debug(u"Serving revocation list to %s in PEM format", req.context.get("remote_addr"))
                resp.body = export_crl()
        else:
            logger.debug(u"Client %s asked revocation list in unsupported format" % req.context.get("remote_addr"))
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/x-pkcs7-crl or application/x-pem-file")
