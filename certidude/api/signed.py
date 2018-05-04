
import falcon
import logging
import json
import hashlib
from certidude.decorators import csrf_protection
from xattr import listxattr, getxattr
from .utils import AuthorityHandler
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)

class SignedCertificateDetailResource(AuthorityHandler):
    def on_get(self, req, resp, cn):

        preferred_type = req.client_prefers(("application/json", "application/x-pem-file"))
        try:
            path, buf, cert, signed, expires = self.authority.get_signed(cn)
        except EnvironmentError:
            logger.warning("Failed to serve non-existant certificate %s to %s",
                cn, req.context.get("remote_addr"))
            raise falcon.HTTPNotFound()

        if preferred_type == "application/x-pem-file":
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.pem" % cn))
            resp.body = buf
            logger.debug("Served certificate %s to %s as application/x-pem-file",
                cn, req.context.get("remote_addr"))
        elif preferred_type == "application/json":
            resp.set_header("Content-Type", "application/json")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.json" % cn))
            try:
                signer_username = getxattr(path, "user.signature.username").decode("ascii")
            except IOError:
                signer_username = None

            attributes = {}
            for key in listxattr(path):
                if key.startswith(b"user.machine."):
                    attributes[key[13:].decode("ascii")] = getxattr(path, key).decode("ascii")

            # TODO: dedup
            resp.body = json.dumps(dict(
                common_name = cn,
                signer = signer_username,
                serial = "%040x" % cert.serial_number,
                organizational_unit = cert.subject.native.get("organizational_unit_name"),
                signed = cert["tbs_certificate"]["validity"]["not_before"].native.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                expires = cert["tbs_certificate"]["validity"]["not_after"].native.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                sha256sum = hashlib.sha256(buf).hexdigest(),
                attributes = attributes or None,
                lease = None,
                extensions = dict([
                    (e["extn_id"].native, e["extn_value"].native)
                    for e in cert["tbs_certificate"]["extensions"]
                    if e["extn_id"].native in ("extended_key_usage",)])

            ))
            logger.debug("Served certificate %s to %s as application/json",
                cn, req.context.get("remote_addr"))
        else:
            logger.debug("Client did not accept application/json or application/x-pem-file")
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json or application/x-pem-file")

    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        self.authority.revoke(cn,
            reason=req.get_param("reason", default="key_compromise"),
            user=req.context.get("user")
        )

