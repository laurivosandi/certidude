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
        try:
            path, buf, cert, attribs = authority.get_attributes(cn)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            script = config.SCRIPT_DEFAULT
            tags = []
            try:
                for tag in attribs.get("user").get("xdg").get("tags").split(","):
                    if "=" in tag:
                        k, v = tag.split("=", 1)
                    else:
                        k, v = "other", tag
                    if k == "script":
                        script = v
                    tags.append(dict(id=tag, key=k, value=v))
            except AttributeError: # No tags
                pass

            resp.set_header("Content-Type", "text/x-shellscript")
            resp.body = env.get_template(script).render(
                authority_name=const.FQDN,
                common_name=cn,
                tags=tags,
                attributes=attribs.get("user").get("machine"))
            logger.info("Served script %s for %s at %s" % (script, cn, req.context["remote_addr"]))
        # TODO: Assert time is within reasonable range
