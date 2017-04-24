import click
import falcon
import logging
import hashlib
import random
import string
from datetime import datetime
from time import time
from certidude import mailer
from certidude.user import User
from certidude import config, authority
from certidude.auth import login_required, authorize_admin

logger = logging.getLogger(__name__)

KEYWORDS = (
    (u"Android", u"android"),
    (u"iPhone", u"iphone"),
    (u"iPad", u"ipad"),
    (u"Ubuntu", u"ubuntu"),
    (u"Fedora", u"fedora"),
    (u"Linux", u"linux"),
    (u"Macintosh", u"mac"),
)

class TokenResource(object):
    def on_get(self, req, resp):
        # Consume token
        now = time()
        timestamp = req.get_param_as_int("t", required=True)
        username = req.get_param("u", required=True)
        user = User.objects.get(username)
        csum = hashlib.sha256()
        csum.update(config.TOKEN_SECRET)
        csum.update(username)
        csum.update(str(timestamp))

        margin = 300 # Tolerate 5 minute clock skew as Kerberos does
        if csum.hexdigest() != req.get_param("c", required=True):
            raise falcon.HTTPUnauthorized("Forbidden", "Invalid token supplied, did you copy-paste link correctly?")
        if now < timestamp - margin:
            raise falcon.HTTPUnauthorized("Forbidden", "Token not valid yet, are you sure server clock is correct?")
        if now > timestamp + margin + config.TOKEN_LIFETIME:
            raise falcon.HTTPUnauthorized("Forbidden", "Token expired")

        # At this point consider token to be legitimate

        common_name = username
        if config.USER_MULTIPLE_CERTIFICATES:
            for key, value in KEYWORDS:
                if key in req.user_agent:
                    device_identifier = value
                    break
            else:
                device_identifier = u"unknown-device"
            common_name = u"%s@%s-%s" % (common_name, device_identifier, \
                hashlib.sha256(req.user_agent).hexdigest()[:8])

        logger.info(u"Signing bundle %s for %s", common_name, req.context.get("user"))
        if config.BUNDLE_FORMAT == "p12":
            resp.set_header("Content-Type", "application/x-pkcs12")
            resp.set_header("Content-Disposition", "attachment; filename=%s.p12" % common_name.encode("ascii"))
            resp.body, cert = authority.generate_pkcs12_bundle(common_name,
                owner=req.context.get("user"))
        elif config.BUNDLE_FORMAT == "ovpn":
            resp.set_header("Content-Type", "application/x-openvpn")
            resp.set_header("Content-Disposition", "attachment; filename=%s.ovpn" % common_name.encode("ascii"))
            resp.body, cert = authority.generate_ovpn_bundle(common_name,
                owner=req.context.get("user"))
        else:
            raise ValueError("Unknown bundle format %s" % config.BUNDLE_FORMAT)


    @login_required
    @authorize_admin
    def on_post(self, req, resp):
        # Generate token
        issuer = req.context.get("user")
        username = req.get_param("user", required=True)
        user = User.objects.get(username)
        timestamp = int(time())
        csum = hashlib.sha256()
        csum.update(config.TOKEN_SECRET)
        csum.update(username)
        csum.update(str(timestamp))
        args = "u=%s&t=%d&c=%s" % (username, timestamp, csum.hexdigest())

        # Token lifetime in local time, to select timezone: dpkg-reconfigure tzdata
        token_created = datetime.fromtimestamp(timestamp)
        token_expires = datetime.fromtimestamp(timestamp + config.TOKEN_LIFETIME)
        with open("/etc/timezone") as fh:
            token_timezone = fh.read().strip()

        context = globals()
        context.update(locals())
        mailer.send("token.md", to=user, **context)
