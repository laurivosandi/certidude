
import falcon
import logging
from certidude import authority
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

logger = logging.getLogger("api")

class SignedCertificateListResource(object):
    @serialize
    @authorize_admin
    def on_get(self, req, resp):
        for j in authority.list_signed():
            yield omit(
                key_type=j.key_type,
                key_length=j.key_length,
                identity=j.identity,
                cn=j.common_name,
                c=j.country_code,
                st=j.state_or_county,
                l=j.city,
                o=j.organization,
                ou=j.organizational_unit,
                fingerprint=j.fingerprint())


class SignedCertificateDetailResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        # Compensate for NTP lag
        from time import sleep
        sleep(5)
        try:
            logger.info("Served certificate %s to %s", cn, req.env["REMOTE_ADDR"])
            resp.set_header("Content-Disposition", "attachment; filename=%s.crt" % cn)
            return authority.get_signed(cn)
        except FileNotFoundError:
            logger.warning("Failed to serve non-existant certificate %s to %s", cn, req.env["REMOTE_ADDR"])
            resp.body = "No certificate CN=%s found" % cn
            raise falcon.HTTPNotFound()

    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        logger.info("Revoked certificate %s by %s from %s", cn, req.context["user"], req.env["REMOTE_ADDR"])
        authority.revoke_certificate(cn)

