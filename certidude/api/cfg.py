import falcon
import logging
import ipaddress
import string
from random import choice
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger("api")

env = Environment(loader=FileSystemLoader("/etc/certidude/scripts"), trim_blocks=True)

SQL_SELECT_INHERITED = """
select `key`, `value` from tag_inheritance where tag_id in (select
	tag.id
from
	device_tag
join
	tag on device_tag.tag_id = tag.id
join
	device on device_tag.device_id = device.id
where
	device.cn = %s)
"""

SQL_SELECT_TAGS = """
select
	tag.`key` as `key`,
	tag.`value` as `value`
from
	device_tag
join
	tag on device_tag.tag_id = tag.id
join
	device on device_tag.device_id = device.id
where
    device.cn = %s
"""

SQL_SELECT_INHERITANCE = """
select
    tag_inheritance.`id` as `id`,
    tag.id as `tag_id`,
    tag.`key` as `match_key`,
    tag.`value` as `match_value`,
    tag_inheritance.`key` as `key`,
    tag_inheritance.`value` as `value`
from tag_inheritance
join tag on tag.id = tag_inheritance.tag_id
"""

class ConfigResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(SQL_SELECT_INHERITANCE)
        def g():
            for row in cursor:
                yield row
            cursor.close()
            conn.close()
        return g()

class ScriptResource(object):
    def on_get(self, req, resp):
        from certidude.api.whois import address_to_identity

        node = address_to_identity(
            config.DATABASE_POOL.get_connection(),
            ipaddress.ip_address(req.env["REMOTE_ADDR"])
        )
        if not node:
            resp.body = "Could not map IP address: %s" % req.env["REMOTE_ADDR"]
            resp.status = falcon.HTTP_404
            return

        address, acquired, identity = node

        key, common_name = identity.split("=")
        assert "=" not in common_name

        conn = config.DATABASE_POOL.get_connection()
        cursor = conn.cursor()

        resp.set_header("Content-Type", "text/x-shellscript")

        args = common_name,
        ctx = dict()

        for query in SQL_SELECT_INHERITED, SQL_SELECT_TAGS:
            cursor.execute(query, args)

            for key, value in cursor:
                current = ctx
                if "." in key:
                    path, key = key.rsplit(".", 1)

                    for component in path.split("."):
                        if component not in current:
                            current[component] = dict()
                        current = current[component]
                current[key] = value
        cursor.close()
        conn.close()

        resp.body = env.get_template("uci.sh").render(ctx)

        # TODO: Assert time is within reasonable range
