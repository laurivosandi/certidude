import falcon
import logging
import re
from xattr import setxattr, listxattr, removexattr
from certidude import push
from certidude.decorators import serialize, csrf_protection
from certidude.firewall import whitelist_subject
from certidude.auth import login_required, authorize_admin

logger = logging.getLogger(__name__)

class AttributeResource(object):
    def __init__(self, authority, namespace):
        self.authority = authority
        self.namespace = namespace

    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, cn):
        """
        Return extended attributes stored on the server.
        This not only contains tags and lease information,
        but might also contain some other sensitive information.
        Results made available only to lease IP address.
        """
        try:
            path, buf, cert, attribs = self.authority.get_attributes(cn, namespace=self.namespace)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            return attribs

    @csrf_protection
    @whitelist_subject # TODO: sign instead
    def on_post(self, req, resp, cn):
        namespace = ("user.%s." % self.namespace).encode("ascii")
        try:
            path, buf, cert, signed, expires = self.authority.get_signed(cn)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            for key in req.params:
                if not re.match("[a-z0-9_\.]+$", key):
                    raise falcon.HTTPBadRequest("Invalid key")
            valid = set()
            for key, value in req.params.items():
                identifier = ("user.%s.%s" % (self.namespace, key)).encode("ascii")
                setxattr(path, identifier, value.encode("utf-8"))
                valid.add(identifier)
            for key in listxattr(path):
                if not key.startswith(namespace):
                    continue
                if key not in valid:
                    removexattr(path, key)
            push.publish("attribute-update", cn)

