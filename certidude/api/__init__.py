# encoding: utf-8

import falcon
import mimetypes
import logging
import os
import click
import hashlib
from datetime import datetime, timedelta
from time import sleep
from xattr import listxattr, getxattr
from certidude import authority, mailer
from certidude.auth import login_required, authorize_admin
from certidude.user import User
from certidude.decorators import serialize, csrf_protection
from certidude import const, config

logger = logging.getLogger(__name__)


class CertificateAuthorityResource(object):
    def on_get(self, req, resp):
        logger.info("Served CA certificate to %s", req.context.get("remote_addr"))
        resp.stream = open(config.AUTHORITY_CERTIFICATE_PATH, "rb")
        resp.append_header("Content-Type", "application/x-x509-ca-cert")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" %
            const.HOSTNAME.encode("ascii"))


class SessionResource(object):
    @csrf_protection
    @serialize
    @login_required
    def on_get(self, req, resp):

        def serialize_requests(g):
            for common_name, path, buf, req, submitted, server in g():
                try:
                    submission_address = getxattr(path, "user.request.address").decode("ascii") # TODO: move to authority.py
                except IOError:
                    submission_address = None
                try:
                    submission_hostname = getxattr(path, "user.request.hostname").decode("ascii") # TODO: move to authority.py
                except IOError:
                    submission_hostname = None
                yield dict(
                    server = authority.server_flags(common_name),
                    submitted = submitted,
                    common_name = common_name,
                    address = submission_address,
                    hostname = submission_hostname if submission_hostname != submission_address else None,
                    md5sum = hashlib.md5(buf).hexdigest(),
                    sha1sum = hashlib.sha1(buf).hexdigest(),
                    sha256sum = hashlib.sha256(buf).hexdigest(),
                    sha512sum = hashlib.sha512(buf).hexdigest()
                )

        def serialize_revoked(g):
            for common_name, path, buf, cert, signed, expired, revoked in g():
                yield dict(
                    serial = "%x" % cert.serial_number,
                    common_name = common_name,
                    # TODO: key type, key length, key exponent, key modulo
                    signed = signed,
                    expired = expired,
                    revoked = revoked,
                    sha256sum = hashlib.sha256(buf).hexdigest())

        def serialize_certificates(g):
            for common_name, path, buf, cert, signed, expires in g():
                # Extract certificate tags from filesystem
                try:
                    tags = []
                    for tag in getxattr(path, "user.xdg.tags").decode("ascii").split(","):
                        if "=" in tag:
                            k, v = tag.split("=", 1)
                        else:
                            k, v = "other", tag
                        tags.append(dict(id=tag, key=k, value=v))
                except IOError: # No such attribute(s)
                    tags = None

                attributes = {}
                for key in listxattr(path):
                    if key.startswith(b"user.machine."):
                        attributes[key[13:].decode("ascii")] = getxattr(path, key).decode("ascii")

                # Extract lease information from filesystem
                try:
                    last_seen = datetime.strptime(getxattr(path, "user.lease.last_seen").decode("ascii"), "%Y-%m-%dT%H:%M:%S.%fZ")
                    lease = dict(
                        inner_address = getxattr(path, "user.lease.inner_address").decode("ascii"),
                        outer_address = getxattr(path, "user.lease.outer_address").decode("ascii"),
                        last_seen = last_seen,
                        age = datetime.utcnow() - last_seen
                    )
                except IOError: # No such attribute(s)
                    lease = None

                try:
                    signer_username = getxattr(path, "user.signature.username").decode("ascii")
                except IOError:
                    signer_username = None

                yield dict(
                    serial = "%x" % cert.serial_number,
                    organizational_unit = cert.subject.native.get("organizational_unit_name"),
                    common_name = common_name,
                    # TODO: key type, key length, key exponent, key modulo
                    signed = signed,
                    expires = expires,
                    sha256sum = hashlib.sha256(buf).hexdigest(),
                    signer = signer_username,
                    lease = lease,
                    tags = tags,
                    attributes = attributes or None,
                    extensions = dict([
                        (e["extn_id"].native, e["extn_value"].native)
                        for e in cert["tbs_certificate"]["extensions"]
                        if e["extn_value"] in ("extended_key_usage",)])
                )

        if req.context.get("user").is_admin():
            logger.info("Logged in authority administrator %s from %s" % (req.context.get("user"), req.context.get("remote_addr")))
        else:
            logger.info("Logged in authority user %s from %s" % (req.context.get("user"), req.context.get("remote_addr")))
        return dict(
            user = dict(
                name=req.context.get("user").name,
                gn=req.context.get("user").given_name,
                sn=req.context.get("user").surname,
                mail=req.context.get("user").mail
            ),
            request_submission_allowed = config.REQUEST_SUBMISSION_ALLOWED,
            authority = dict(
                builder = dict(
                    profiles = config.IMAGE_BUILDER_PROFILES
                ),
                tagging = [dict(name=t[0], type=t[1], title=t[2]) for t in config.TAG_TYPES],
                lease = dict(
                    offline = 600, # Seconds from last seen activity to consider lease offline, OpenVPN reneg-sec option
                    dead = 604800 # Seconds from last activity to consider lease dead, X509 chain broken or machine discarded
                ),
                common_name = const.FQDN,
                title = authority.certificate.subject.native["common_name"],
                mailer = dict(
                    name = config.MAILER_NAME,
                    address = config.MAILER_ADDRESS
                ) if config.MAILER_ADDRESS else None,
                machine_enrollment_allowed=config.MACHINE_ENROLLMENT_ALLOWED,
                user_enrollment_allowed=config.USER_ENROLLMENT_ALLOWED,
                user_multiple_certificates=config.USER_MULTIPLE_CERTIFICATES,
                events = config.EVENT_SOURCE_SUBSCRIBE % config.EVENT_SOURCE_TOKEN,
                requests=serialize_requests(authority.list_requests),
                signed=serialize_certificates(authority.list_signed),
                revoked=serialize_revoked(authority.list_revoked),
                admin_users = User.objects.filter_admins(),
                user_subnets = config.USER_SUBNETS or None,
                autosign_subnets = config.AUTOSIGN_SUBNETS or None,
                request_subnets = config.REQUEST_SUBNETS or None,
                admin_subnets=config.ADMIN_SUBNETS or None,
                signature = dict(
                    revocation_list_lifetime=config.REVOCATION_LIST_LIFETIME,
                    profiles = [dict(name=k, server=v[0]=="server", lifetime=v[1], organizational_unit=v[2], title=v[3]) for k,v in config.PROFILES.items()]
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
            raise falcon.HTTPBadRequest()

        if os.path.isdir(path):
            path = os.path.join(path, "index.html")

        if os.path.exists(path):
            content_type, content_encoding = mimetypes.guess_type(path)
            if content_type:
                resp.append_header("Content-Type", content_type)
            if content_encoding:
                resp.append_header("Content-Encoding", content_encoding)
            resp.stream = open(path, "rb")
            logger.debug("Serving '%s' from '%s'", req.path, path)
        else:
            resp.status = falcon.HTTP_404
            resp.body = "File '%s' not found" % req.path
            logger.info("File '%s' not found, path resolved to '%s'", req.path, path)
import ipaddress

class NormalizeMiddleware(object):
    def process_request(self, req, resp, *args):
        assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"
        req.context["remote_addr"] = ipaddress.ip_address(req.access_route[0])

def certidude_app(log_handlers=[]):
    from certidude import config
    from .signed import SignedCertificateDetailResource
    from .request import RequestListResource, RequestDetailResource
    from .lease import LeaseResource, LeaseDetailResource
    from .script import ScriptResource
    from .tag import TagResource, TagDetailResource
    from .attrib import AttributeResource
    from .bootstrap import BootstrapResource
    from .token import TokenResource
    from .builder import ImageBuilderResource

    app = falcon.API(middleware=NormalizeMiddleware())
    app.req_options.auto_parse_form_urlencoded = True
    #app.req_options.strip_url_path_trailing_slash = False

    # Certificate authority API calls
    app.add_route("/api/certificate/", CertificateAuthorityResource())
    app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource())
    app.add_route("/api/request/{cn}/", RequestDetailResource())
    app.add_route("/api/request/", RequestListResource())
    app.add_route("/api/", SessionResource())

    if config.USER_ENROLLMENT_ALLOWED: # TODO: add token enable/disable flag for config
        app.add_route("/api/token/", TokenResource())

    # Extended attributes for scripting etc.
    app.add_route("/api/signed/{cn}/attr/", AttributeResource(authority, namespace="machine"))
    app.add_route("/api/signed/{cn}/script/", ScriptResource())

    # API calls used by pushed events on the JS end
    app.add_route("/api/signed/{cn}/tag/", TagResource())
    app.add_route("/api/signed/{cn}/lease/", LeaseDetailResource())

    # API call used to delete existing tags
    app.add_route("/api/signed/{cn}/tag/{tag}/", TagDetailResource())

    # Gateways can submit leases via this API call
    app.add_route("/api/lease/", LeaseResource())

    # Bootstrap resource
    app.add_route("/api/bootstrap/", BootstrapResource())

    # LEDE image builder resource
    app.add_route("/api/build/{profile}/{suggested_filename}", ImageBuilderResource())

    # Add CRL handler if we have any whitelisted subnets
    if config.CRL_SUBNETS:
        from .revoked import RevocationListResource
        app.add_route("/api/revoked/", RevocationListResource())

    # Add SCEP handler if we have any whitelisted subnets
    if config.SCEP_SUBNETS:
        from .scep import SCEPResource
        app.add_route("/api/scep/", SCEPResource())

    # Add sink for serving static files
    app.add_sink(StaticResource(os.path.join(__file__, "..", "..", "static")))

    if config.OCSP_SUBNETS:
        from .ocsp import OCSPResource
        app.add_sink(OCSPResource(), prefix="/api/ocsp")

    # Set up log handlers
    if config.LOGGING_BACKEND == "sql":
        from certidude.mysqllog import LogHandler
        from certidude.api.log import LogResource
        uri = config.cp.get("logging", "database")
        log_handlers.append(LogHandler(uri))
        app.add_route("/api/log/", LogResource(uri))
    elif config.LOGGING_BACKEND == "syslog":
        from logging.handlers import SyslogHandler
        log_handlers.append(SysLogHandler())
        # Browsing syslog via HTTP is obviously not possible out of the box
    elif config.LOGGING_BACKEND:
        raise ValueError("Invalid logging.backend = %s" % config.LOGGING_BACKEND)

    return app
