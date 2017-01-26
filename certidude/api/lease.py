
from datetime import datetime
from pyasn1.codec.der import decoder
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

OIDS = {
    (2, 5, 4,  3) : 'CN',   # common name
    (2, 5, 4,  6) : 'C',    # country
    (2, 5, 4,  7) : 'L',    # locality
    (2, 5, 4,  8) : 'ST',   # stateOrProvince
    (2, 5, 4, 10) : 'O',    # organization
    (2, 5, 4, 11) : 'OU',   # organizationalUnit
}

def parse_dn(data):
    chunks, remainder = decoder.decode(data)
    dn = ""
    if remainder:
        raise ValueError()
    # TODO: Check for duplicate entries?
    def generate():
        for chunk in chunks:
            for chunkette in chunk:
                key, value = chunkette
                yield str(OIDS[key] + "=" + value)
    return ", ".join(generate())


class StatusFileLeaseResource(object):
    def __init__(self, uri):
        self.uri = uri

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        from openvpn_status import parse_status
        from urllib import urlopen
        fh = urlopen(self.uri)
        status = parse_status(fh.read())
        for cn, e in status.routing_table.items():
            yield {
                "acquired": status.client_list[cn].connected_since,
                "released": None,
                "address":  e.virtual_address,
                "identity": "CN=%s" % cn, # BUGBUG
            }


class LeaseResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        from ipaddress import ip_address

        # BUGBUG
        SQL_LEASES = """
            select
                acquired,
                released,
                address,
                identities.data as identity
            from
                addresses
            right join
                identities
            on
                identities.id = addresses.identity
            where
                addresses.released <> 1
            order by
                addresses.id
            desc
        """
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor()
        cursor.execute(SQL_LEASES)

        for acquired, released, address, identity in cursor:
            yield {
                "acquired": datetime.utcfromtimestamp(acquired),
                "released": datetime.utcfromtimestamp(released) if released else None,
                "address":  ip_address(bytes(address)),
                "identity": parse_dn(bytes(identity))
            }

        cursor.close()
        conn.close()
