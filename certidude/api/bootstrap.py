import logging
from certidude.decorators import serialize
from certidude.config import cp
from certidude import authority, config, const
from jinja2 import Template

logger = logging.getLogger(__name__)

class BootstrapResource(object):
    def on_get(self, req, resp):
        resp.body = Template(open(config.BOOTSTRAP_TEMPLATE).read()).render(
            authority = const.FQDN,
            servers = authority.list_server_names())

