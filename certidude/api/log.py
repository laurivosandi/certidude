
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

class LogResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        """
        Translate currently online client's IP-address to distinguished name
        """

        SQL_LOG_ENTRIES = """
            SELECT
                *
            FROM
                log
            ORDER BY created DESC
        """
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(SQL_LOG_ENTRIES)

        def g():
            for row in cursor:
                yield row
            cursor.close()
            conn.close()
        return tuple(g())

#        for acquired, released, identity in cursor:
#            return {
#                "acquired": datetime.utcfromtimestamp(acquired),
#                "identity": parse_dn(bytes(identity))
#            }
#        return None
        
