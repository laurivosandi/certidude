
import falcon
import logging
import binascii
import click
import gssapi
import ldap
import os
import re
import simplepam
import socket
from asn1crypto import pem, x509
from base64 import b64decode
from certidude.user import User
from certidude import config, const

logger = logging.getLogger(__name__)

def whitelist_subnets(subnets):
    """
    Validate source IP address of API call against subnet list
    """
    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            # Check for administration subnet whitelist
            for subnet in subnets:
                if req.context.get("remote_addr") in subnet:
                    break
            else:
                logger.info("Rejected access to administrative call %s by %s from %s, source address not whitelisted",
                    req.env["PATH_INFO"],
                    req.context.get("user", "unauthenticated user"),
                    req.context.get("remote_addr"))
                raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % req.context.get("remote_addr"))

            return func(self, req, resp, *args, **kwargs)
        return wrapped
    return wrapper

def whitelist_content_types(*content_types):
    def wrapper(func):
        def wrapped(self, req, resp, *args, **kwargs):
            for content_type in content_types:
                if req.get_header("Content-Type") == content_type:
                    return func(self, req, resp, *args, **kwargs)
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only %s content type" % ", ".join(content_types))
        return wrapped
    return wrapper

def whitelist_subject(func):
    def wrapped(self, req, resp, cn, *args, **kwargs):
        from ipaddress import ip_address
        from certidude import authority
        from xattr import getxattr
        try:
            path, buf, cert, signed, expires = authority.get_signed(cn)
        except IOError:
            raise falcon.HTTPNotFound()
        else:
            # First attempt to authenticate client with certificate
            buf = req.get_header("X-SSL-CERT")
            if buf:
                header, _, der_bytes = pem.unarmor(buf.replace("\t", "").encode("ascii"))
                origin_cert = x509.Certificate.load(der_bytes)
                if origin_cert.native == cert.native:
                    logger.debug("Subject authenticated using certificates")
                    return func(self, req, resp, cn, *args, **kwargs)

            # For backwards compatibility check source IP address
            # TODO: make it disableable
            try:
                inner_address = getxattr(path, "user.lease.inner_address").decode("ascii")
            except IOError:
                raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % req.context.get("remote_addr"))
            else:
                if req.context.get("remote_addr") != ip_address(inner_address):
                    raise falcon.HTTPForbidden("Forbidden", "Remote address %s mismatch" % req.context.get("remote_addr"))
                else:
                    return func(self, req, resp, cn, *args, **kwargs)
    return wrapped


def authenticate(optional=False):
    def wrapper(func):
        def wrapped(resource, req, resp, *args, **kwargs):
            kerberized = False

            if "kerberos" in config.AUTHENTICATION_BACKENDS:
                for subnet in config.KERBEROS_SUBNETS:
                    if req.context.get("remote_addr") in subnet:
                        kerberized = True

            if not req.auth: # no credentials provided
                if optional: # optional allowed
                    req.context["user"] = None
                    return func(resource, req, resp, *args, **kwargs)

                if kerberized:
                    logger.debug("No Kerberos ticket offered while attempting to access %s from %s",
                        req.env["PATH_INFO"], req.context.get("remote_addr"))
                    raise falcon.HTTPUnauthorized("Unauthorized",
                        "No Kerberos ticket offered, are you sure you've logged in with domain user account?",
                        ["Negotiate"])
                else:
                    logger.debug("No credentials offered while attempting to access %s from %s",
                        req.env["PATH_INFO"], req.context.get("remote_addr"))
                    raise falcon.HTTPUnauthorized("Unauthorized", "Please authenticate", ("Basic",))

            if kerberized:
                if not req.auth.startswith("Negotiate "):
                    raise falcon.HTTPBadRequest("Bad request",
                        "Bad header, expected Negotiate: %s" % req.auth)

                os.environ["KRB5_KTNAME"] = config.KERBEROS_KEYTAB

                try:
                    server_creds = gssapi.creds.Credentials(
                        usage='accept',
                        name=gssapi.names.Name('HTTP/%s'% const.FQDN))
                except gssapi.raw.exceptions.BadNameError:
                    logger.error("Failed initialize HTTP service principal, possibly bad permissions for %s or /etc/krb5.conf" %
                        config.KERBEROS_KEYTAB)
                    raise

                context = gssapi.sec_contexts.SecurityContext(creds=server_creds)

                token = ''.join(req.auth.split()[1:])

                try:
                    context.step(b64decode(token))
                except binascii.Error: # base64 errors
                    raise falcon.HTTPBadRequest("Bad request", "Malformed token")
                except gssapi.raw.exceptions.BadMechanismError:
                    raise falcon.HTTPBadRequest("Bad request", "Unsupported authentication mechanism (NTLM?) was offered. Please make sure you've logged into the computer with domain user account. The web interface should not prompt for username or password.")

                try:
                    username, realm = str(context.initiator_name).split("@")
                except AttributeError: # TODO: Better exception
                    raise falcon.HTTPForbidden("Failed to determine username, are you trying to log in with correct domain account?")

                if realm != config.KERBEROS_REALM:
                    raise falcon.HTTPForbidden("Forbidden",
                        "Cross-realm trust not supported")

                if username.endswith("$") and optional:
                    # Extract machine hostname
                    # TODO: Assert LDAP group membership
                    req.context["machine"] = username[:-1].lower()
                    req.context["user"] = None
                else:
                    # Attempt to look up real user
                    req.context["user"] = User.objects.get(username)

                logger.debug("Succesfully authenticated user %s for %s from %s",
                    req.context["user"], req.env["PATH_INFO"], req.context["remote_addr"])
                return func(resource, req, resp, *args, **kwargs)

            else:
                if not req.auth.startswith("Basic "):
                    raise falcon.HTTPBadRequest("Bad request", "Bad header, expected Basic: %s" % req.auth)
                basic, token = req.auth.split(" ", 1)
                user, passwd = b64decode(token).decode("ascii").split(":", 1)

            if config.AUTHENTICATION_BACKENDS == {"pam"}:
                if not simplepam.authenticate(user, passwd, "sshd"):
                    logger.critical("Basic authentication failed for user %s from  %s, "
                        "are you sure server process has read access to /etc/shadow?",
                        repr(user), req.context.get("remote_addr"))
                    raise falcon.HTTPUnauthorized("Forbidden", "Invalid password", ("Basic",))
                conn = None
            elif "ldap" in config.AUTHENTICATION_BACKENDS:
                upn = "%s@%s" % (user, config.KERBEROS_REALM)
                click.echo("Connecting to %s as %s" % (config.LDAP_AUTHENTICATION_URI, upn))
                conn = ldap.initialize(config.LDAP_AUTHENTICATION_URI, bytes_mode=False)
                conn.set_option(ldap.OPT_REFERRALS, 0)

                try:
                    conn.simple_bind_s(upn, passwd)
                except ldap.STRONG_AUTH_REQUIRED:
                    logger.critical("LDAP server demands encryption, use ldaps:// instead of ldaps://")
                    raise
                except ldap.SERVER_DOWN:
                    logger.critical("Failed to connect LDAP server at %s, are you sure LDAP server's CA certificate has been copied to this machine?",
                        config.LDAP_AUTHENTICATION_URI)
                    raise
                except ldap.INVALID_CREDENTIALS:
                    logger.critical("LDAP bind authentication failed for user %s from  %s",
                        repr(user), req.context.get("remote_addr"))
                    raise falcon.HTTPUnauthorized("Forbidden",
                        "Please authenticate with %s domain account username" % const.DOMAIN,
                        ("Basic",))

                req.context["ldap_conn"] = conn
            else:
                raise NotImplementedError("No suitable authentication method configured")

            try:
                req.context["user"] = User.objects.get(user)
            except User.DoesNotExist:
                raise falcon.HTTPUnauthorized("Unauthorized", "Invalid credentials", ("Basic",))

            retval = func(resource, req, resp, *args, **kwargs)
            if conn:
                conn.unbind_s()
            return retval
        return wrapped
    return wrapper


def login_required(func):
    return authenticate()(func)

def login_optional(func):
    return authenticate(optional=True)(func)

def authorize_admin(func):
    @whitelist_subnets(config.ADMIN_SUBNETS)
    def wrapped(resource, req, resp, *args, **kwargs):
        if req.context.get("user").is_admin():
            return func(resource, req, resp, *args, **kwargs)
        logger.info("User '%s' not authorized to access administrative API", req.context.get("user").name)
        raise falcon.HTTPForbidden("Forbidden", "User not authorized to perform administrative operations")
    return wrapped

def authorize_server(func):
    """
    Make sure the request originator has a certificate with server flags
    """
    from asn1crypto import pem, x509
    def wrapped(resource, req, resp, *args, **kwargs):
        buf = req.get_header("X-SSL-CERT")
        if not buf:
            logger.info("No TLS certificate presented to access administrative API call")
            raise falcon.HTTPForbidden("Forbidden", "Machine not authorized to perform the operation")

        header, _, der_bytes = pem.unarmor(buf.replace("\t", "").encode("ascii"))
        cert = x509.Certificate.load(der_bytes) # TODO: validate serial
        for extension in cert["tbs_certificate"]["extensions"]:
            if extension["extn_id"].native == "extended_key_usage":
                if "server_auth" in extension["extn_value"].native:
                    req.context["machine"] = cert.subject.native["common_name"]
                    return func(resource, req, resp, *args, **kwargs)
        logger.info("TLS authenticated machine '%s' not authorized to access administrative API", cert.subject.native["common_name"])
        raise falcon.HTTPForbidden("Forbidden", "Machine not authorized to perform the operation")
    return wrapped
