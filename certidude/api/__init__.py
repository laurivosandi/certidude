# encoding: utf-8

import falcon
import mimetypes
import logging
import os
import click
from datetime import datetime
from time import sleep
from certidude import authority, mailer
from certidude.auth import login_required, authorize_admin
from certidude.user import User
from certidude.decorators import serialize, event_source, csrf_protection
from certidude.wrappers import Request, Certificate
from certidude import const, config

logger = logging.getLogger("api")

class CertificateStatusResource(object):
    """
    openssl ocsp -issuer CAcert_class1.pem -serial 0x<serial no in hex> -url http://localhost -CAfile cacert_both.pem
    """
    def on_post(self, req, resp):
        ocsp_request = req.stream.read(req.content_length)
        for component in decoder.decode(ocsp_request):
            click.echo(component)
        resp.append_header("Content-Type", "application/ocsp-response")
        resp.status = falcon.HTTP_200
        raise NotImplementedError()


class CertificateAuthorityResource(object):
    def on_get(self, req, resp):
        logger.info(u"Served CA certificate to %s", req.context.get("remote_addr"))
        resp.stream = open(config.AUTHORITY_CERTIFICATE_PATH, "rb")
        resp.append_header("Content-Type", "application/x-x509-ca-cert")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" %
            const.HOSTNAME.encode("ascii"))


class SessionResource(object):
    @csrf_protection
    @serialize
    @login_required
    @event_source
    def on_get(self, req, resp):
        return dict(
            user = dict(
                name=req.context.get("user").name,
                gn=req.context.get("user").given_name,
                sn=req.context.get("user").surname,
                mail=req.context.get("user").mail
            ),
            request_submission_allowed = sum( # Dirty hack!
                [req.context.get("remote_addr") in j
                    for j in config.REQUEST_SUBNETS]),
            authority = dict(
                outbox = dict(
                    server = config.OUTBOX,
                    name = config.OUTBOX_NAME,
                    mail = config.OUTBOX_MAIL
                ),
                user_certificate_enrollment=config.USER_CERTIFICATE_ENROLLMENT,
                user_mutliple_certificates=config.USER_MULTIPLE_CERTIFICATES,
                certificate = authority.certificate,
                events = config.EVENT_SOURCE_SUBSCRIBE % config.EVENT_SOURCE_TOKEN,
                requests=authority.list_requests(),
                signed=authority.list_signed(),
                revoked=authority.list_revoked(),
                admin_users = User.objects.filter_admins(),
                user_subnets = config.USER_SUBNETS,
                autosign_subnets = config.AUTOSIGN_SUBNETS,
                request_subnets = config.REQUEST_SUBNETS,
                admin_subnets=config.ADMIN_SUBNETS,
                signature = dict(
                    certificate_lifetime=config.CERTIFICATE_LIFETIME,
                    revocation_list_lifetime=config.REVOCATION_LIST_LIFETIME
                )
            ) if req.context.get("user").is_admin() else None,
            features=dict(
                tagging=config.TAGGING_BACKEND,
                leases=config.LEASES_BACKEND,
                logging=config.LOGGING_BACKEND))


class StaticResource(object):
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def __call__(self, req, resp):

        path = os.path.realpath(os.path.join(self.root, req.path[1:]))
        if not path.startswith(self.root):
            raise falcon.HTTPForbidden

        if os.path.isdir(path):
            path = os.path.join(path, "index.html")
        click.echo("Serving: %s" % path)

        if os.path.exists(path):
            content_type, content_encoding = mimetypes.guess_type(path)
            if content_type:
                resp.append_header("Content-Type", content_type)
            if content_encoding:
                resp.append_header("Content-Encoding", content_encoding)
            resp.stream = open(path, "rb")
        else:
            resp.status = falcon.HTTP_404
            resp.body = "File '%s' not found" % req.path

import ipaddress

class NormalizeMiddleware(object):
    def process_request(self, req, resp, *args):
        assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"
        req.context["remote_addr"] = ipaddress.ip_address(req.env["REMOTE_ADDR"].decode("utf-8"))

    def process_response(self, req, resp, resource=None):
        # wtf falcon?!
        if isinstance(resp.location, unicode):
            resp.location = resp.location.encode("ascii")

def certidude_app():
    from certidude import config
    from .bundle import BundleResource
    from .revoked import RevocationListResource
    from .signed import SignedCertificateListResource, SignedCertificateDetailResource
    from .request import RequestListResource, RequestDetailResource
    from .lease import LeaseResource, StatusFileLeaseResource
    from .whois import WhoisResource
    from .tag import TagResource, TagDetailResource
    from .cfg import ConfigResource, ScriptResource

    app = falcon.API(middleware=NormalizeMiddleware())

    # Certificate authority API calls
    app.add_route("/api/ocsp/", CertificateStatusResource())
    app.add_route("/api/certificate/", CertificateAuthorityResource())
    app.add_route("/api/revoked/", RevocationListResource())
    app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource())
    app.add_route("/api/signed/", SignedCertificateListResource())
    app.add_route("/api/request/{cn}/", RequestDetailResource())
    app.add_route("/api/request/", RequestListResource())
    app.add_route("/api/", SessionResource())

    # Gateway API calls, should this be moved to separate project?
    if config.LEASES_BACKEND == "openvpn-status":
        app.add_route("/api/lease/", StatusFileLeaseResource(config.OPENVPN_STATUS_URI))
    elif config.LEASES_BACKEND == "sql":
        app.add_route("/api/lease/", LeaseResource())
        app.add_route("/api/whois/", WhoisResource())

    # Optional user enrollment API call
    if config.USER_CERTIFICATE_ENROLLMENT:
        app.add_route("/api/bundle/", BundleResource())

    if config.TAGGING_BACKEND == "sql":
        uri = config.cp.get("tagging", "database")
        app.add_route("/api/tag/", TagResource(uri))
        app.add_route("/api/tag/{identifier}/", TagDetailResource(uri))
        app.add_route("/api/config/", ConfigResource(uri))
        app.add_route("/api/script/", ScriptResource(uri))
    elif config.TAGGING_BACKEND:
        raise ValueError("Invalid tagging.backend = %s" % config.TAGGING_BACKEND)


    return app
