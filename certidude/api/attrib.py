import falcon
import logging
from ipaddress import ip_address
from datetime import datetime
from certidude import config, authority
from certidude.decorators import serialize

logger = logging.getLogger(__name__)

class AttributeResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        """
        Return extended attributes stored on the server.
        This not only contains tags and lease information,
        but might also contain some other sensitive information.
        Results made available only to lease IP address.
        """
        try:
            path, buf, cert, attribs = authority.get_attributes(cn)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            try:
                whitelist = ip_address(attribs.get("user").get("lease").get("address").decode("ascii"))
            except AttributeError: # TODO: probably race condition
                raise falcon.HTTPForbidden("Forbidden",
                    "Attributes only accessible to the machine")

            if req.context.get("remote_addr") != whitelist:
                logger.info("Attribute access denied from %s, expected %s for %s",
                    req.context.get("remote_addr"),
                    whitelist,
                    cn)
                raise falcon.HTTPForbidden("Forbidden",
                    "Attributes only accessible to the machine")

            return attribs
