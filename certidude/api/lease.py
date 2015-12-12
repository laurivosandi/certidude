
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


class LeaseResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        from ipaddress import ip_address

        # BUGBUG
        SQL_LEASES = """
            SELECT
                acquired,
                released,
                address,
                identities.data as identity
            FROM
                addresses
            RIGHT JOIN
                identities
            ON
                identities.id = addresses.identity
            WHERE
                addresses.released <> 1
        """
        cnx = config.DATABASE_POOL.get_connection()
        cursor = cnx.cursor()
        cursor.execute(SQL_LEASES)

        for acquired, released, address, identity in cursor:
            yield {
                "acquired": datetime.utcfromtimestamp(acquired),
                "released": datetime.utcfromtimestamp(released) if released else None,
                "address":  ip_address(bytes(address)),
                "identity": parse_dn(bytes(identity))
            }

