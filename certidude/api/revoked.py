
import logging
from certidude.authority import export_crl

logger = logging.getLogger("api")

class RevocationListResource(object):
    def on_get(self, req, resp):
        logger.debug("Revocation list requested by %s", req.context.get("remote_addr"))
        resp.set_header("Content-Type", "application/x-pkcs7-crl")
        resp.append_header("Content-Disposition", "attachment; filename=ca.crl")
        resp.body = export_crl()
