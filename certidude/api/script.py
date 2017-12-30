import falcon
import logging
from certidude import const, config, authority
from certidude.decorators import serialize
from jinja2 import Environment, FileSystemLoader
from certidude.firewall import whitelist_subject

logger = logging.getLogger(__name__)
env = Environment(loader=FileSystemLoader(config.SCRIPT_DIR), trim_blocks=True)

class ScriptResource():
    @whitelist_subject
    def on_get(self, req, resp, cn):
        path, buf, cert, attribs = authority.get_attributes(cn)
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

        script = named_tags.get("script", config.SCRIPT_DEFAULT)
        resp.set_header("Content-Type", "text/x-shellscript")
        resp.body = env.get_template(script).render(
            authority_name=const.FQDN,
            common_name=cn,
            other_tags=other_tags,
            named_tags=named_tags,
            attributes=attribs.get("user").get("machine"))
        logger.info("Served script %s for %s at %s" % (script, cn, req.context["remote_addr"]))
        # TODO: Assert time is within reasonable range
