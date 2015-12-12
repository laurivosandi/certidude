
import falcon
import ipaddress
from certidude import config
from certidude.decorators import serialize

def address_to_identity(cnx, addr):
    """
    Translate currently online client's IP-address to distinguished name
    """

    SQL_LEASES = """
        SELECT
            acquired,
            released,
            identities.data as identity
        FROM
            addresses
        RIGHT JOIN
            identities
        ON
            identities.id = addresses.identity
        WHERE
            address = %s AND
            released IS NOT NULL
    """

    cursor = cnx.cursor()
    import struct
    cursor.execute(SQL_LEASES, (struct.pack("!L", int(addr)),))

    for acquired, released, identity in cursor:
        return {
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
