import falcon
import logging
import os
import re
import xattr
from datetime import datetime
from certidude import config, push
from certidude.auth import login_required, authorize_admin, authorize_server
from certidude.decorators import serialize
from .utils import AuthorityHandler

logger = logging.getLogger(__name__)

# TODO: lease namespacing (?)

class LeaseDetailResource(AuthorityHandler):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, cn):
        try:
            path, buf, cert, signed, expires = self.authority.get_signed(cn)
            return dict(
                last_seen =     xattr.getxattr(path, "user.lease.last_seen").decode("ascii"),
                inner_address = xattr.getxattr(path, "user.lease.inner_address").decode("ascii"),
                outer_address = xattr.getxattr(path, "user.lease.outer_address").decode("ascii")
            )
        except EnvironmentError: # Certificate or attribute not found
            raise falcon.HTTPNotFound()


class LeaseResource(AuthorityHandler):
    @authorize_server
    def on_post(self, req, resp):
        client_common_name = req.get_param("client", required=True)
        m = re.match("CN=(.+?),", client_common_name) # It's actually DN, resolve it to CN
        if m:
            client_common_name, = m.groups()

        path, buf, cert, signed, expires = self.authority.get_signed(client_common_name) # TODO: catch exceptions
        if req.get_param("serial") and cert.serial_number != req.get_param_as_int("serial"): # OCSP-ish solution for OpenVPN, not exposed for StrongSwan
            raise falcon.HTTPForbidden("Forbidden", "Invalid serial number supplied")
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        xattr.setxattr(path, "user.lease.outer_address", req.get_param("outer_address", required=True).encode("ascii"))
        xattr.setxattr(path, "user.lease.inner_address", req.get_param("inner_address", required=True).encode("ascii"))
        xattr.setxattr(path, "user.lease.last_seen", now)
        push.publish("lease-update", client_common_name)

        server_common_name = req.context.get("machine")
        path = os.path.join(config.SIGNED_DIR, server_common_name + ".pem")
        xattr.setxattr(path, "user.lease.outer_address", "")
        xattr.setxattr(path, "user.lease.inner_address", "%s" % req.context.get("remote_addr"))
        xattr.setxattr(path, "user.lease.last_seen", now)
        push.publish("lease-update", server_common_name)

        # client-disconnect is pretty much unusable:
        # - Android Connect Client results "IP packet with unknown IP version=2" on gateway
        # - NetworkManager just kills OpenVPN client, disconnect is never reported
        # - Disconnect is also not reported when uplink connection dies or laptop goes to sleep
