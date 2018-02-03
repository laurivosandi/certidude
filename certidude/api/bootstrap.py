import logging
from certidude.decorators import serialize
from certidude.config import cp
from certidude import config, const
from jinja2 import Template

logger = logging.getLogger(__name__)

class BootstrapResource(object):
    def __init__(self, authority):
        self.authority = authority

    def on_get(self, req, resp):
        resp.body = Template(open(config.BOOTSTRAP_TEMPLATE).read()).render(
            authority = const.FQDN,
            servers = self.authority.list_server_names())

