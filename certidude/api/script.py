import falcon
import logging
from certidude import config, authority
from certidude.decorators import serialize
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)
env = Environment(loader=FileSystemLoader(config.SCRIPT_DIR), trim_blocks=True)

class ScriptResource():
    def on_get(self, req, resp, cn):

        try:
            path, buf, cert, attribs = authority.get_attributes(cn)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            resp.set_header("Content-Type", "text/x-shellscript")
            resp.body = env.get_template(config.SCRIPT_DEFAULT).render(attributes=attribs)

        # TODO: Assert time is within reasonable range
