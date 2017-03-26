
import click
import xattr
from datetime import datetime
from pyasn1.codec.der import decoder
from certidude import config, authority, push
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

# TODO: lease namespacing (?)

class LeaseDetailResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, cn):
        path, buf, cert = authority.get_signed(cn)
        return dict(
            last_seen = xattr.getxattr(path, "user.last_seen"),
            address = xattr.getxattr(path, "user.address").decode("ascii")
        )


class LeaseResource(object):
    def on_post(self, req, resp):
        # TODO: verify signature
        common_name = req.get_param("client", required=True)
        path, buf, cert = authority.get_signed(common_name) # TODO: catch exceptions
        if cert.serial != req.get_param_as_int("serial", required=True): # Badum we have OCSP!
            raise # TODO proper exception
        if req.get_param("action") == "client-connect":
            xattr.setxattr(path, "user.address", req.get_param("address", required=True).encode("ascii"))
            xattr.setxattr(path, "user.last_seen", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
            push.publish("lease-update", common_name)

        # client-disconnect is pretty much unusable:
        # - Android Connect Client results "IP packet with unknown IP version=2" on gateway
        # - NetworkManager just kills OpenVPN client, disconnect is never reported
        # - Disconnect is also not reported when uplink connection dies or laptop goes to sleep
