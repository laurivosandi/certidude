import click
import falcon
import logging
import hashlib
import random
import string
from asn1crypto import pem
from asn1crypto.csr import CertificationRequest
from datetime import datetime
from time import time
from certidude import mailer
from certidude.decorators import serialize
from certidude.user import User
from certidude import config
from certidude.auth import login_required, authorize_admin

logger = logging.getLogger(__name__)

class TokenResource(object):
    def __init__(self, authority):
        self.authority = authority

    def on_put(self, req, resp):
        # Consume token
        now = time()
        timestamp = req.get_param_as_int("t", required=True)
        username = req.get_param("u", required=True)
        user = User.objects.get(username)
        csum = hashlib.sha256()
        csum.update(config.TOKEN_SECRET)
        csum.update(username.encode("ascii"))
        csum.update(str(timestamp).encode("ascii"))

        margin = 300 # Tolerate 5 minute clock skew as Kerberos does
        if csum.hexdigest() != req.get_param("c", required=True):
            raise falcon.HTTPForbidden("Forbidden", "Invalid token supplied, did you copy-paste link correctly?")
        if now < timestamp - margin:
            raise falcon.HTTPForbidden("Forbidden", "Token not valid yet, are you sure server clock is correct?")
        if now > timestamp + margin + config.TOKEN_LIFETIME:
            raise falcon.HTTPForbidden("Forbidden", "Token expired")

        # At this point consider token to be legitimate
        body = req.stream.read(req.content_length)
        header, _, der_bytes = pem.unarmor(body)
        csr = CertificationRequest.load(der_bytes)
        common_name = csr["certification_request_info"]["subject"].native["common_name"]
        assert common_name == username or common_name.startswith(username + "@"), "Invalid common name %s" % common_name
        try:
            _, resp.body = self.authority._sign(csr, body)
            resp.set_header("Content-Type", "application/x-pem-file")
            logger.info("Autosigned %s as proven by token ownership", common_name)
        except FileExistsError:
            logger.info("Won't autosign duplicate %s", common_name)
            raise falcon.HTTPConflict(
                "Certificate with such common name (CN) already exists",
                "Will not overwrite existing certificate signing request, explicitly delete existing one and try again")


    @serialize
    @login_required
    @authorize_admin
    def on_post(self, req, resp):
        # Generate token
        issuer = req.context.get("user")
        username = req.get_param("username")
        secondary = req.get_param("mail")

        if username:
            # Otherwise try to look up user so we can derive their e-mail address
            user = User.objects.get(username)
        else:
            # If no username is specified, assume it's intended for someone outside domain
            username = "guest-%s" % hashlib.sha256(secondary.encode("ascii")).hexdigest()[-8:]
            if not secondary:
                raise

        timestamp = int(time())
        csum = hashlib.sha256()
        csum.update(config.TOKEN_SECRET)
        csum.update(username.encode("ascii"))
        csum.update(str(timestamp).encode("ascii"))
        args = "u=%s&t=%d&c=%s&i=%s" % (username, timestamp, csum.hexdigest(), issuer.name)

        # Token lifetime in local time, to select timezone: dpkg-reconfigure tzdata
        token_created = datetime.fromtimestamp(timestamp)
        token_expires = datetime.fromtimestamp(timestamp + config.TOKEN_LIFETIME)
        try:
            with open("/etc/timezone") as fh:
                token_timezone = fh.read().strip()
        except EnvironmentError:
            token_timezone = None
        url = "%s#%s" % (config.TOKEN_URL, args)
        context = globals()
        context.update(locals())
        mailer.send("token.md", to=user, **context)
        return {
            "token": args,
            "url": url,
        }
