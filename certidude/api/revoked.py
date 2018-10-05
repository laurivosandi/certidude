import falcon
import logging
from certidude import const, config
from .utils import AuthorityHandler
from .utils.firewall import whitelist_subnets

logger = logging.getLogger(__name__)

class RevocationListResource(AuthorityHandler):
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
            resp.body = self.authority.export_crl(pem=False)
        elif req.client_accepts("application/x-pem-file"):
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s-crl.pem" % const.HOSTNAME))
            logger.debug("Serving revocation list (PEM) to %s", req.context.get("remote_addr"))
            resp.body = self.authority.export_crl()
        else:
            logger.debug("Client %s asked revocation list in unsupported format" % req.context.get("remote_addr"))
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/x-pkcs7-crl or application/x-pem-file")


class RevokedCertificateDetailResource(AuthorityHandler):
    def on_get(self, req, resp, serial_number):
        try:
            path, buf, cert, signed, expires, revoked, reason = self.authority.get_revoked(serial_number)
        except EnvironmentError:
            logger.warning("Failed to serve non-existant revoked certificate with serial %s to %s",
                serial_number, req.context.get("remote_addr"))
            raise falcon.HTTPNotFound()
        resp.set_header("Content-Type", "application/x-pem-file")
        resp.set_header("Content-Disposition", ("attachment; filename=%x.pem" % cert.serial_number))
        resp.body = buf
        logger.debug("Served revoked certificate with serial %s to %s",
            serial_number, req.context.get("remote_addr"))
