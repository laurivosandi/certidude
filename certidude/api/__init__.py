# encoding: utf-8

import falcon
import mimetypes
import logging
import os
import click
import hashlib
import xattr
from datetime import datetime
from time import sleep
from certidude import authority, mailer
from certidude.auth import login_required, authorize_admin
from certidude.user import User
from certidude.decorators import serialize, event_source, csrf_protection
from cryptography.x509.oid import NameOID
from certidude import const, config

logger = logging.getLogger(__name__)

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
        def serialize_requests(g):
            for common_name, path, buf, obj, server in g():
                yield dict(
                    common_name = common_name,
                    server = server,
                    md5sum = hashlib.md5(buf).hexdigest(),
                    sha1sum = hashlib.sha1(buf).hexdigest(),
                    sha256sum = hashlib.sha256(buf).hexdigest(),
                    sha512sum = hashlib.sha512(buf).hexdigest()
                )

        def serialize_certificates(g):
            for common_name, path, buf, obj, server in g():
                # Extract certificate tags from filesystem
                try:
                    tags = []
                    for tag in xattr.getxattr(path, "user.xdg.tags").split(","):
                        if "=" in tag:
                            k, v = tag.split("=", 1)
                        else:
                            k, v = "other", tag
                        tags.append(dict(id=tag, key=k, value=v))
                except IOError: # No such attribute(s)
                    tags = None

                # Extract lease information from filesystem
                try:
                    last_seen = datetime.strptime(xattr.getxattr(path, "user.lease.last_seen"), "%Y-%m-%dT%H:%M:%S.%fZ")
                    lease = dict(
                        address = xattr.getxattr(path, "user.lease.address"),
                        last_seen = last_seen,
                        age = datetime.utcnow() - last_seen
                    )
                except IOError: # No such attribute(s)
                    lease = None

                yield dict(
                    serial_number = "%x" % obj.serial_number,
                    common_name = common_name,
                    server = server,
                    # TODO: key type, key length, key exponent, key modulo
                    signed = obj.not_valid_before,
                    expires = obj.not_valid_after,
                    sha256sum = hashlib.sha256(buf).hexdigest(),
                    lease = lease,
                    tags = tags
                )

        if req.context.get("user").is_admin():
            logger.info("Logged in authority administrator %s" % req.context.get("user"))
        else:
            logger.info("Logged in authority user %s" % req.context.get("user"))
        return dict(
            user = dict(
                name=req.context.get("user").name,
                gn=req.context.get("user").given_name,
                sn=req.context.get("user").surname,
                mail=req.context.get("user").mail
            ),
            request_submission_allowed = config.REQUEST_SUBMISSION_ALLOWED,
            authority = dict(
                tagging = [dict(name=t[0], type=t[1], title=t[2]) for t in config.TAG_TYPES],
                lease = dict(
                    offline = 600, # Seconds from last seen activity to consider lease offline, OpenVPN reneg-sec option
                    dead = 604800 # Seconds from last activity to consider lease dead, X509 chain broken or machine discarded
                ),
                common_name = authority.ca_cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME)[0].value,
                outbox = dict(
                    server = config.OUTBOX,
                    name = config.OUTBOX_NAME,
                    mail = config.OUTBOX_MAIL
                ),
                machine_enrollment_allowed=config.MACHINE_ENROLLMENT_ALLOWED,
                user_enrollment_allowed=config.USER_ENROLLMENT_ALLOWED,
                user_multiple_certificates=config.USER_MULTIPLE_CERTIFICATES,
                events = config.EVENT_SOURCE_SUBSCRIBE % config.EVENT_SOURCE_TOKEN,
                requests=serialize_requests(authority.list_requests),
                signed=serialize_certificates(authority.list_signed),
                revoked=serialize_certificates(authority.list_revoked),
                users=User.objects.all(),
                admin_users = User.objects.filter_admins(),
                user_subnets = config.USER_SUBNETS,
                autosign_subnets = config.AUTOSIGN_SUBNETS,
                request_subnets = config.REQUEST_SUBNETS,
                admin_subnets=config.ADMIN_SUBNETS,
                signature = dict(
                    server_certificate_lifetime=config.SERVER_CERTIFICATE_LIFETIME,
                    client_certificate_lifetime=config.CLIENT_CERTIFICATE_LIFETIME,
                    revocation_list_lifetime=config.REVOCATION_LIST_LIFETIME
                )
            ) if req.context.get("user").is_admin() else None,
            features=dict(
                tagging=True,
                leases=True,
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
    from .signed import SignedCertificateDetailResource
    from .request import RequestListResource, RequestDetailResource
    from .lease import LeaseResource, LeaseDetailResource
    from .cfg import ConfigResource, ScriptResource
    from .tag import TagResource, TagDetailResource
    from .attrib import AttributeResource

    app = falcon.API(middleware=NormalizeMiddleware())
    app.req_options.auto_parse_form_urlencoded = True

    # Certificate authority API calls
    app.add_route("/api/ocsp/", CertificateStatusResource())
    app.add_route("/api/certificate/", CertificateAuthorityResource())
    app.add_route("/api/revoked/", RevocationListResource())
    app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource())
    app.add_route("/api/request/{cn}/", RequestDetailResource())
    app.add_route("/api/request/", RequestListResource())
    app.add_route("/api/", SessionResource())

    # Extended attributes for scripting etc.
    app.add_route("/api/signed/{cn}/attr/", AttributeResource())

    # API calls used by pushed events on the JS end
    app.add_route("/api/signed/{cn}/tag/", TagResource())
    app.add_route("/api/signed/{cn}/lease/", LeaseDetailResource())

    # API call used to delete existing tags
    app.add_route("/api/signed/{cn}/tag/{tag}/", TagDetailResource())

    # Gateways can submit leases via this API call
    app.add_route("/api/lease/", LeaseResource())

    # Optional user enrollment API call
    if config.USER_ENROLLMENT_ALLOWED:
        app.add_route("/api/bundle/", BundleResource())

    return app
