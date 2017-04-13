
import click
import logging
import os
import re
import socket
from base64 import b64decode
from certidude.user import User
from certidude.firewall import whitelist_subnets
from certidude import config, const

logger = logging.getLogger("api")

if "kerberos" in config.AUTHENTICATION_BACKENDS:
    import gssapi
    os.environ["KRB5_KTNAME"] = config.KERBEROS_KEYTAB
    server_creds = gssapi.creds.Credentials(
        usage='accept',
        name=gssapi.names.Name('HTTP/%s'% (socket.gethostname())))
    click.echo("Accepting requests only for realm: %s" % const.DOMAIN)


def authenticate(optional=False):
    import falcon
    def wrapper(func):
        def kerberos_authenticate(resource, req, resp, *args, **kwargs):
            # If LDAP enabled and device is not Kerberos capable fall
            # back to LDAP bind authentication
            if "ldap" in config.AUTHENTICATION_BACKENDS:
                if "Android" in req.user_agent or "iPhone" in req.user_agent:
                    return ldap_authenticate(resource, req, resp, *args, **kwargs)

            # Try pre-emptive authentication
            if not req.auth:
                if optional:
                    req.context["user"] = None
                    return func(resource, req, resp, *args, **kwargs)

                logger.debug(u"No Kerberos ticket offered while attempting to access %s from %s",
                    req.env["PATH_INFO"], req.context.get("remote_addr"))
                raise falcon.HTTPUnauthorized("Unauthorized",
                    "No Kerberos ticket offered, are you sure you've logged in with domain user account?",
                    ["Negotiate"])

            context = gssapi.sec_contexts.SecurityContext(creds=server_creds)
            token = ''.join(req.auth.split()[1:])
            context.step(b64decode(token))
            username, domain = str(context.initiator_name).split("@")

            if domain.lower() != const.DOMAIN.lower():
                raise falcon.HTTPForbidden("Forbidden",
                    "Invalid realm supplied")

            if username.endswith("$") and optional:
                # Extract machine hostname
                # TODO: Assert LDAP group membership
                req.context["machine"] = username[:-1].lower()
                req.context["user"] = None
            else:
                # Attempt to look up real user
                req.context["user"] = User.objects.get(username)

            logger.debug(u"Succesfully authenticated user %s for %s from %s",
                req.context["user"], req.env["PATH_INFO"], req.context["remote_addr"])
            return func(resource, req, resp, *args, **kwargs)


        def ldap_authenticate(resource, req, resp, *args, **kwargs):
            """
            Authenticate against LDAP with WWW Basic Auth credentials
            """

            if optional and not req.get_param_as_bool("authenticate"):
                return func(resource, req, resp, *args, **kwargs)

            import ldap

            if not req.auth:
                raise falcon.HTTPUnauthorized("Unauthorized",
                    "No authentication header provided",
                    ("Basic",))

            if not req.auth.startswith("Basic "):
                raise falcon.HTTPForbidden("Forbidden", "Bad header: %s" % req.auth)

            from base64 import b64decode
            basic, token = req.auth.split(" ", 1)
            user, passwd = b64decode(token).split(":", 1)

            click.echo("Connecting to %s as %s" % (config.LDAP_AUTHENTICATION_URI, user))
            conn = ldap.initialize(config.LDAP_AUTHENTICATION_URI)
            conn.set_option(ldap.OPT_REFERRALS, 0)

            try:
                conn.simple_bind_s("%s@%s" % (user, const.DOMAIN), passwd)
            except ldap.STRONG_AUTH_REQUIRED:
                logger.critical("LDAP server demands encryption, use ldaps:// instead of ldaps://")
                raise
            except ldap.SERVER_DOWN:
                logger.critical("Failed to connect LDAP server at %s, are you sure LDAP server's CA certificate has been copied to this machine?",
                    config.LDAP_AUTHENTICATION_URI)
                raise
            except ldap.INVALID_CREDENTIALS:
                logger.critical(u"LDAP bind authentication failed for user %s from  %s",
                    repr(user), req.context.get("remote_addr"))
                raise falcon.HTTPUnauthorized("Forbidden",
                    "Please authenticate with %s domain account username" % const.DOMAIN,
                    ("Basic",))

            req.context["ldap_conn"] = conn
            req.context["user"] = User.objects.get(user)
            retval = func(resource, req, resp, *args, **kwargs)
            conn.unbind_s()
            return retval


        def pam_authenticate(resource, req, resp, *args, **kwargs):
            """
            Authenticate against PAM with WWW Basic Auth credentials
            """

            if optional and not req.get_param_as_bool("authenticate"):
                return func(resource, req, resp, *args, **kwargs)

            if not req.auth:
                raise falcon.HTTPUnauthorized("Forbidden", "Please authenticate", ("Basic",))

            if not req.auth.startswith("Basic "):
                raise falcon.HTTPForbidden("Forbidden", "Bad header: %s" % req.auth)

            basic, token = req.auth.split(" ", 1)
            user, passwd = b64decode(token).split(":", 1)

            import simplepam
            if not simplepam.authenticate(user, passwd, "sshd"):
                logger.critical(u"Basic authentication failed for user %s from  %s",
                    repr(user), req.context.get("remote_addr"))
                raise falcon.HTTPUnauthorized("Forbidden", "Invalid password", ("Basic",))

            req.context["user"] = User.objects.get(user)
            return func(resource, req, resp, *args, **kwargs)

        if "kerberos" in config.AUTHENTICATION_BACKENDS:
            return kerberos_authenticate
        elif config.AUTHENTICATION_BACKENDS == {"pam"}:
            return pam_authenticate
        elif config.AUTHENTICATION_BACKENDS == {"ldap"}:
            return ldap_authenticate
        else:
            raise NotImplementedError("Authentication backend %s not supported" % config.AUTHENTICATION_BACKENDS)
    return wrapper


def login_required(func):
    return authenticate()(func)

def login_optional(func):
    return authenticate(optional=True)(func)

def authorize_admin(func):
    def whitelist_authorize_admin(resource, req, resp, *args, **kwargs):
        # Check for username whitelist
        if not req.context.get("user") or req.context.get("user") not in config.ADMIN_WHITELIST:
            logger.info(u"Rejected access to administrative call %s by %s from %s, user not whitelisted",
                req.env["PATH_INFO"], req.context.get("user"), req.context.get("remote_addr"))
            raise falcon.HTTPForbidden("Forbidden", "User %s not whitelisted" % req.context.get("user"))
        return func(resource, req, resp, *args, **kwargs)

    def authorize_admin(resource, req, resp, *args, **kwargs):
        if req.context.get("user").is_admin():
            req.context["admin_authorized"] = True
            return func(resource, req, resp, *args, **kwargs)
        logger.info(u"User '%s' not authorized to access administrative API", req.context.get("user").name)
        raise falcon.HTTPForbidden("Forbidden", "User not authorized to perform administrative operations")

    if config.AUTHORIZATION_BACKEND == "whitelist":
        return whitelist_authorize_admin
    return authorize_admin
