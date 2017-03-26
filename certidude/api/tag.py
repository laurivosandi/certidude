import falcon
import logging
import xattr
from certidude import authority
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize, csrf_protection

logger = logging.getLogger("api")

class TagResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, cn):
        path, buf, cert = authority.get_signed(cn)
        return dict([
            (k[9:], xattr.getxattr(path, k))
            for k in xattr.listxattr(path)
            if k.startswith("user.tag.")])

    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, cn):
        from certidude import push
        path, buf, cert = authority.get_signed(cn)
        key, value = req.get_param("key", required=True), req.get_param("value", required=True)
        xattr.setxattr(path, "user.tag.%s" % key, value.encode("utf-8"))
        logger.debug(u"Tag %s=%s set for %s" % (key, value, cn))
        push.publish("tag-update", cn)


class TagDetailResource(object):
    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn, key):
        from certidude import push
        path, buf, cert = authority.get_signed(cn)
        xattr.removexattr(path, "user.tag.%s" % key)
        logger.debug(u"Tag %s removed for %s" % (key, cn))
        push.publish("tag-update", cn)
