import falcon
import logging
import ipaddress
import string
from random import choice
from certidude import config
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize
from certidude.relational import RelationalMixin
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)
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
"""


SQL_SELECT_RULES = """
select
    tag.cn as `cn`,
    tag.key as `tag_key`,
    tag.value as `tag_value`,
    tag_properties.property_key as `property_key`,
    tag_properties.property_value as `property_value`
from
    tag_properties
join
    tag
on
    tag.key = tag_properties.tag_key and
    tag.value = tag_properties.tag_value
"""


class ConfigResource(RelationalMixin):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        return self.iterfetch(SQL_SELECT_TAGS)


class ScriptResource(RelationalMixin):
    def on_get(self, req, resp):
        from certidude.api.whois import address_to_identity

        node = address_to_identity(
            self.connect(),
            req.context.get("remote_addr")
        )
        if not node:
            resp.body = "Could not map IP address: %s" % req.context.get("remote_addr")
            resp.status = falcon.HTTP_404
            return

        address, acquired, identity = node

        key, common_name = identity.split("=")
        assert "=" not in common_name

        conn = self.connect()
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
