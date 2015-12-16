
import falcon
import logging
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

logger = logging.getLogger("api")

class TagResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("select * from tag")

        def g():
            for row in cursor:
                yield row
            cursor.close()
            conn.close()
        return tuple(g())

    @serialize
    @login_required
    @authorize_admin
    def on_post(self, req, resp):
        from certidude import push
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor()
        args = req.get_param("cn"), req.get_param("key"), req.get_param("value")
        cursor.execute(
            "insert into tag (`cn`, `key`, `value`) values (%s, %s, %s)", args)
        push.publish("tag-added", str(cursor.lastrowid))
        logger.debug("Tag cn=%s, key=%s, value=%s added" % args)
        conn.commit()
        cursor.close()
        conn.close()


class TagDetailResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, identifier):
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("select * from tag where `id` = %s", (identifier,))
        for row in cursor:
            cursor.close()
            conn.close()
            return row
        cursor.close()
        conn.close()
        raise falcon.HTTPNotFound()

    @serialize
    @login_required
    @authorize_admin
    def on_put(self, req, resp, identifier):
        from certidude import push
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor()
        cursor.execute("update tag set `value` = %s where `id` = %s limit 1",
            (req.get_param("value"), identifier))
        conn.commit()
        cursor.close()
        conn.close()
        logger.debug("Tag %s updated, value set to %s",
            identifier, req.get_param("value"))
        push.publish("tag-updated", identifier)


    @serialize
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, identifier):
        from certidude import push
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor()
        cursor.execute("delete from tag where tag.id = %s", (identifier,))
        conn.commit()
        cursor.close()
        conn.close()
        push.publish("tag-removed", identifier)
        logger.debug("Tag %s removed" % identifier)


