
import falcon
import logging
from certidude import authority
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize, csrf_protection

logger = logging.getLogger("api")

class SignedCertificateListResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        return {"signed":authority.list_signed()}


class SignedCertificateDetailResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        # Compensate for NTP lag
#        from time import sleep
#        sleep(5)
        try:
            cert = authority.get_signed(cn)
        except EnvironmentError:
            logger.warning(u"Failed to serve non-existant certificate %s to %s",
                cn, req.context.get("remote_addr"))
            resp.body = "No certificate CN=%s found" % cn
            raise falcon.HTTPNotFound()
        else:
            logger.debug(u"Served certificate %s to %s",
                cn, req.context.get("remote_addr"))
            return cert


    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        logger.info(u"Revoked certificate %s by %s from %s",
            cn, req.context.get("user"), req.context.get("remote_addr"))
        authority.revoke_certificate(cn)

