
import falcon
import logging
from certidude.relational import RelationalMixin
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

logger = logging.getLogger("api")

class TagResource(RelationalMixin):
    SQL_CREATE_TABLES = "tag_tables.sql"

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        return self.iterfetch("select * from tag")


    @serialize
    @login_required
    @authorize_admin
    def on_post(self, req, resp):
        from certidude import push
        args = req.get_param("cn"), req.get_param("key"), req.get_param("value")
        rowid = self.sql_execute("tag_insert.sql", *args)
        push.publish("tag-added", str(rowid))
        logger.debug("Tag cn=%s, key=%s, value=%s added" % args)


class TagDetailResource(RelationalMixin):
    SQL_CREATE_TABLES = "tag_tables.sql"

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, identifier):
        conn = self.sql_connect()
        cursor = conn.cursor()
        if self.uri.scheme == "mysql":
            cursor.execute("select `cn`, `key`, `value` from tag where id = %s", (identifier,))
        else:
            cursor.execute("select `cn`, `key`, `value` from tag where id = ?", (identifier,))
        cols = [j[0] for j in cursor.description]
        for row in cursor:
            cursor.close()
            conn.close()
            return dict(zip(cols, row))
        cursor.close()
        conn.close()
        raise falcon.HTTPNotFound()


    @serialize
    @login_required
    @authorize_admin
    def on_put(self, req, resp, identifier):
        from certidude import push
        args = req.get_param("value"), identifier
        self.sql_execute("tag_update.sql", *args)
        logger.debug("Tag %s updated, value set to %s",
            identifier, req.get_param("value"))
        push.publish("tag-updated", identifier)


    @serialize
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, identifier):
        from certidude import push
        self.sql_execute("tag_delete.sql", identifier)
        push.publish("tag-removed", identifier)
        logger.debug("Tag %s removed" % identifier)
