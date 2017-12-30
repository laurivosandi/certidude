import falcon
import logging
from xattr import getxattr, removexattr, setxattr
from certidude import authority, push
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize, csrf_protection

logger = logging.getLogger(__name__)

class TagResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp, cn):
        path, buf, cert, signed, expires = authority.get_signed(cn)
        tags = []
        try:
            for tag in getxattr(path, "user.xdg.tags").decode("utf-8").split(","):
                if "=" in tag:
                    k, v = tag.split("=", 1)
                else:
                    k, v = "other", tag
                tags.append(dict(id=tag, key=k, value=v))
        except IOError: # No user.xdg.tags attribute
            pass
        return tags


    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, cn):
        path, buf, cert, signed, expires = authority.get_signed(cn)
        key, value = req.get_param("key", required=True), req.get_param("value", required=True)
        try:
            tags = set(getxattr(path, "user.xdg.tags").decode("utf-8").split(","))
        except IOError:
            tags = set()
        if key == "other":
            tags.add(value)
        else:
            tags.add("%s=%s" % (key,value))
        setxattr(path, "user.xdg.tags", ",".join(tags).encode("utf-8"))
        logger.debug("Tag %s=%s set for %s" % (key, value, cn))
        push.publish("tag-update", cn)


class TagDetailResource(object):
    @csrf_protection
    @login_required
    @authorize_admin
    def on_put(self, req, resp, cn, tag):
        path, buf, cert, signed, expires = authority.get_signed(cn)
        value = req.get_param("value", required=True)
        try:
            tags = set(getxattr(path, "user.xdg.tags").decode("utf-8").split(","))
        except IOError:
            tags = set()
        try:
            tags.remove(tag)
        except KeyError:
            pass
        if "=" in tag:
            tags.add("%s=%s" % (tag.split("=")[0], value))
        else:
            tags.add(value)
        setxattr(path, "user.xdg.tags", ",".join(tags).encode("utf-8"))
        logger.debug("Tag %s set to %s for %s" % (tag, value, cn))
        push.publish("tag-update", cn)

    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn, tag):
        path, buf, cert, signed, expires = authority.get_signed(cn)
        tags = set(getxattr(path, "user.xdg.tags").decode("utf-8").split(","))
        tags.remove(tag)
        if not tags:
            removexattr(path, "user.xdg.tags")
        else:
            setxattr(path, "user.xdg.tags", ",".join(tags))
        logger.debug("Tag %s removed for %s" % (tag, cn))
        push.publish("tag-update", cn)
