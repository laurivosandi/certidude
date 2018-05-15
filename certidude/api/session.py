from datetime import datetime
from xattr import listxattr, getxattr
import falcon
import hashlib
import logging
from certidude import const, config
from certidude.common import cert_to_dn
from certidude.decorators import serialize, csrf_protection
from certidude.user import User
from .utils import AuthorityHandler
from .utils.firewall import login_required, authorize_admin

logger = logging.getLogger(__name__)

class CertificateAuthorityResource(object):
    def on_get(self, req, resp):
        logger.info("Served CA certificate to %s", req.context.get("remote_addr"))
        resp.stream = open(config.AUTHORITY_CERTIFICATE_PATH, "rb")
        resp.append_header("Content-Type", "application/x-x509-ca-cert")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" %
            const.HOSTNAME)

class SessionResource(AuthorityHandler):
    def __init__(self, authority, token_manager):
        AuthorityHandler.__init__(self, authority)
        self.token_manager = token_manager

    @csrf_protection
    @serialize
    @login_required
    @authorize_admin
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
            for common_name, path, buf, cert, signed, expired, revoked, reason in g(limit=5):
                yield dict(
                    serial = "%x" % cert.serial_number,
                    common_name = common_name,
                    # TODO: key type, key length, key exponent, key modulo
                    signed = signed,
                    expired = expired,
                    revoked = revoked,
                    reason = reason,
                    sha256sum = hashlib.sha256(buf).hexdigest())

        def serialize_certificates(g):
            for common_name, path, buf, cert, signed, expires in g():
                # Extract certificate tags from filesystem
                try:
                    tags = []
                    for tag in getxattr(path, "user.xdg.tags").decode("utf-8").split(","):
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

                # TODO: dedup
                serialized = dict(
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
                    responder_url = None
                )

                for e in cert["tbs_certificate"]["extensions"].native:
                    if e["extn_id"] == "key_usage":
                        serialized["key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "extended_key_usage":
                        serialized["extended_key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "basic_constraints":
                        serialized["basic_constraints"] = e["extn_value"]
                    elif e["extn_id"] == "crl_distribution_points":
                        for c in e["extn_value"]:
                            serialized["revoked_url"] = c["distribution_point"]
                            break
                        serialized["extended_key_usage"] = e["extn_value"]
                    elif e["extn_id"] == "authority_information_access":
                        for a in e["extn_value"]:
                            if a["access_method"] == "ocsp":
                                serialized["responder_url"] = a["access_location"]
                            else:
                                raise NotImplementedError("Don't know how to handle AIA access method %s" % a["access_method"])
                    elif e["extn_id"] == "authority_key_identifier":
                        pass
                    elif e["extn_id"] == "key_identifier":
                        pass
                    elif e["extn_id"] == "subject_alt_name":
                        serialized["subject_alt_name"], = e["extn_value"]
                    else:
                        raise NotImplementedError("Don't know how to handle extension %s" % e["extn_id"])
                yield serialized

        logger.info("Logged in authority administrator %s from %s with %s" % (
            req.context.get("user"), req.context.get("remote_addr"), req.context.get("user_agent")))
        return dict(
            user = dict(
                name=req.context.get("user").name,
                gn=req.context.get("user").given_name,
                sn=req.context.get("user").surname,
                mail=req.context.get("user").mail
            ),
            request_submission_allowed = config.REQUEST_SUBMISSION_ALLOWED,
            service = dict(
                protocols = config.SERVICE_PROTOCOLS,
                routers = [j[0] for j in self.authority.list_signed(
                    common_name=config.SERVICE_ROUTERS)]
            ),
            builder = dict(
                profiles = config.IMAGE_BUILDER_PROFILES or None
            ),
            authority = dict(
                hostname = const.FQDN,
                tokens = self.token_manager.list() if self.token_manager else None,
                tagging = [dict(name=t[0], type=t[1], title=t[2]) for t in config.TAG_TYPES],
                lease = dict(
                    offline = 600, # Seconds from last seen activity to consider lease offline, OpenVPN reneg-sec option
                    dead = 604800 # Seconds from last activity to consider lease dead, X509 chain broken or machine discarded
                ),
                certificate = dict(
                    algorithm = self.authority.public_key.algorithm,
                    common_name = self.authority.certificate.subject.native["common_name"],
                    distinguished_name = cert_to_dn(self.authority.certificate),
                    md5sum = hashlib.md5(self.authority.certificate_buf).hexdigest(),
                    blob = self.authority.certificate_buf.decode("ascii"),
                    organization = self.authority.certificate["tbs_certificate"]["subject"].native.get("organization_name"),
                    signed = self.authority.certificate["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None),
                    expires = self.authority.certificate["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None)
                ),
                mailer = dict(
                    name = config.MAILER_NAME,
                    address = config.MAILER_ADDRESS
                ) if config.MAILER_ADDRESS else None,
                user_enrollment_allowed=config.USER_ENROLLMENT_ALLOWED,
                user_multiple_certificates=config.USER_MULTIPLE_CERTIFICATES,
                events = config.EVENT_SOURCE_SUBSCRIBE % config.EVENT_SOURCE_TOKEN,
                requests=serialize_requests(self.authority.list_requests),
                signed=serialize_certificates(self.authority.list_signed),
                revoked=serialize_revoked(self.authority.list_revoked),
                signature = dict(
                    revocation_list_lifetime=config.REVOCATION_LIST_LIFETIME,
                    profiles = sorted([p.serialize() for p in config.PROFILES.values()], key=lambda p:p.get("slug")),
                )
            ),
            authorization = dict(
                admin_users = User.objects.filter_admins(),

                user_subnets = config.USER_SUBNETS or None,
                autosign_subnets = config.AUTOSIGN_SUBNETS or None,
                request_subnets = config.REQUEST_SUBNETS or None,
                machine_enrollment_subnets=config.MACHINE_ENROLLMENT_SUBNETS or None,
                admin_subnets=config.ADMIN_SUBNETS or None,

                ocsp_subnets = config.OCSP_SUBNETS or None,
                crl_subnets = config.CRL_SUBNETS or None,
                scep_subnets = config.SCEP_SUBNETS or None,
            ),
            features=dict(
                token=bool(config.TOKEN_URL),
                tagging=True,
                leases=True,
                logging=config.LOGGING_BACKEND)
        )
