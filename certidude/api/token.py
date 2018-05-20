import click
import codecs
import falcon
import logging
import os
import string
from asn1crypto import pem
from asn1crypto.csr import CertificationRequest
from datetime import datetime, timedelta
from time import time
from certidude import mailer, const
from certidude.tokens import TokenManager
from certidude.relational import RelationalMixin
from certidude.decorators import serialize
from certidude.user import User
from certidude import config
from .utils import AuthorityHandler
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)

class TokenResource(AuthorityHandler):
    def __init__(self, authority, manager):
        AuthorityHandler.__init__(self, authority)
        self.manager = manager

    def on_put(self, req, resp):
        try:
            username, mail, created, expires, profile = self.manager.consume(req.get_param("token", required=True))
        except RelationalMixin.DoesNotExist:
            raise falcon.HTTPForbidden("Forbidden", "No such token or token expired")
        body = req.stream.read(req.content_length)
        header, _, der_bytes = pem.unarmor(body)
        csr = CertificationRequest.load(der_bytes)
        common_name = csr["certification_request_info"]["subject"].native["common_name"]
        if not common_name.startswith(username + "@"):
            raise falcon.HTTPBadRequest("Bad requst", "Invalid common name %s" % common_name)
        try:
            _, resp.body = self.authority._sign(csr, body, profile=config.PROFILES.get(profile),
                overwrite=config.TOKEN_OVERWRITE_PERMITTED)
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
        self.manager.issue(
            issuer = req.context.get("user"),
            subject = User.objects.get(req.get_param("username", required=True)),
            subject_mail = req.get_param("mail"))
