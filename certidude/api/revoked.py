
import click
import falcon
import json
import logging
from certidude import const, config
from certidude.authority import export_crl, list_revoked
from certidude.firewall import whitelist_subnets

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
                ("attachment; filename=%s.crl" % const.HOSTNAME))
            # Convert PEM to DER
            logger.debug("Serving revocation list (DER) to %s", req.context.get("remote_addr"))
            resp.body = export_crl(pem=False)
        elif req.client_accepts("application/x-pem-file"):
            if req.get_param_as_bool("wait"):
                url = config.LONG_POLL_SUBSCRIBE % "crl"
                resp.status = falcon.HTTP_SEE_OTHER
                resp.set_header("Location", url)
                logger.debug("Redirecting to CRL request to %s", url)
                resp.body = "Redirecting to %s" % url
            else:
                resp.set_header("Content-Type", "application/x-pem-file")
                resp.append_header(
                    "Content-Disposition",
                    ("attachment; filename=%s-crl.pem" % const.HOSTNAME))
                logger.debug("Serving revocation list (PEM) to %s", req.context.get("remote_addr"))
                resp.body = export_crl()
        else:
            logger.debug("Client %s asked revocation list in unsupported format" % req.context.get("remote_addr"))
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/x-pkcs7-crl or application/x-pem-file")
