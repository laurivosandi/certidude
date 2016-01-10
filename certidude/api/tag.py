
import falcon
import logging
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

logger = logging.getLogger("api")

SQL_TAG_LIST = """
select
    device_tag.id as `id`,
	tag.key as `key`,
	tag.value as `value`,
	device.cn as `cn`
from
	device_tag
join
	tag
on
	device_tag.tag_id = tag.id
join
	device
on
	device_tag.device_id = device.id
"""

SQL_TAG_DETAIL = SQL_TAG_LIST + " where device_tag.id = %s"

class TagResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(SQL_TAG_LIST)

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

        args = req.get_param("cn"),
        cursor.execute(
            "insert ignore device (`cn`) values (%s) on duplicate key update used = NOW();", args)
        device_id = cursor.lastrowid

        args = req.get_param("key"), req.get_param("value")
        cursor.execute(
            "insert into tag (`key`, `value`) values (%s, %s) on duplicate key update used = NOW();", args)
        tag_id = cursor.lastrowid

        args = device_id, tag_id
        cursor.execute(
            "insert into device_tag (`device_id`, `tag_id`) values (%s, %s);", args)

        push.publish("tag-added", str(cursor.lastrowid))

        args = req.get_param("cn"), req.get_param("key"), req.get_param("value")
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
        cursor.execute(SQL_TAG_DETAIL, (identifier,))
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

        # Create tag if necessary
        args = req.get_param("key"), req.get_param("value")
        cursor.execute(
            "insert into tag (`key`, `value`) values (%s, %s) on duplicate key update used = NOW();", args)
        tag_id = cursor.lastrowid

        # Attach tag to device
        cursor.execute("update device_tag set tag_id = %s where `id` = %s limit 1",
            (tag_id, identifier))
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
        cursor.execute("delete from device_tag where id = %s", (identifier,))
        conn.commit()
        cursor.close()
        conn.close()
        push.publish("tag-removed", identifier)
        logger.debug("Tag %s removed" % identifier)


