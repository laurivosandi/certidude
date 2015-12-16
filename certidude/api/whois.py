
import falcon
import ipaddress
from datetime import datetime
from certidude import config
from certidude.decorators import serialize
from certidude.api.lease import parse_dn

def address_to_identity(cnx, addr):
    """
    Translate currently online client's IP-address to distinguished name
    """

    SQL_LEASES = """
        select
            acquired,
            released,
            identities.data as identity
        from
            addresses
        right join
            identities
        on
            identities.id = addresses.identity
        where
            address = %s and
            released is not null
    """

    cursor = cnx.cursor()
    import struct
    cursor.execute(SQL_LEASES, (struct.pack("!L", int(addr)),))

    for acquired, released, identity in cursor:
        return {
            "address": addr,
            "acquired": datetime.utcfromtimestamp(acquired),
            "identity": parse_dn(bytes(identity))
        }
    return None


class WhoisResource(object):
    @serialize
    def on_get(self, req, resp):
        identity = address_to_identity(
            config.DATABASE_POOL.get_connection(),
            ipaddress.ip_address(req.get_param("address") or req.env["REMOTE_ADDR"])
        )

        if identity:
            return identity
        else:
            resp.status = falcon.HTTP_403
            resp.body = "Failed to look up node %s" % req.env["REMOTE_ADDR"]
