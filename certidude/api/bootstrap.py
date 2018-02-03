import logging
from certidude import config, const
from jinja2 import Template
from .utils import AuthorityHandler

logger = logging.getLogger(__name__)

class BootstrapResource(AuthorityHandler):
    def on_get(self, req, resp):
        resp.body = Template(open(config.BOOTSTRAP_TEMPLATE).read()).render(
            authority = const.FQDN,
            servers = self.authority.list_server_names())

