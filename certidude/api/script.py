import falcon
import logging
import os
from certidude import const, config
from certidude.decorators import serialize
from jinja2 import Environment, FileSystemLoader
from certidude.firewall import whitelist_subject
from .utils import AuthorityHandler

logger = logging.getLogger(__name__)
env = Environment(loader=FileSystemLoader(config.SCRIPT_DIR), trim_blocks=True)

class ScriptResource(AuthorityHandler):
    @whitelist_subject
    def on_get(self, req, resp, cn):
        path, buf, cert, attribs = self.authority.get_attributes(cn)
        # TODO: are keys unique?
        named_tags = {}
        other_tags = []

        try:
            for tag in attribs.get("user").get("xdg").get("tags").split(","):
                if "=" in tag:
                    k, v = tag.split("=", 1)
                    named_tags[k] = v
                else:
                    other_tags.append(tag)
        except AttributeError: # No tags
            pass

        script = named_tags.get("script", "default.sh")
        assert script in os.listdir(config.SCRIPT_DIR)
        resp.set_header("Content-Type", "text/x-shellscript")
        resp.body = env.get_template(os.path.join(script)).render(
            authority_name=const.FQDN,
            common_name=cn,
            other_tags=other_tags,
            named_tags=named_tags,
            attributes=attribs.get("user").get("machine"))
        logger.info("Served script %s for %s at %s" % (script, cn, req.context["remote_addr"]))
        # TODO: Assert time is within reasonable range
