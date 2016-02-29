
import click
import falcon
import ipaddress
import kerberos
import logging
import os
import re
import socket
from certidude import config

logger = logging.getLogger("api")

# Vanilla Kerberos provides only username.
# AD also embeds PAC (Privilege Attribute Certificate), which
# is supposed to be sent via HTTP headers and it contains
# the groups user is part of.
# Even then we would have to manually look up the e-mail
# address eg via LDAP, hence to keep things simple
# we simply use Kerberos to authenticate.

FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]

if config.AUTHENTICATION_BACKEND == "kerberos":
    if not os.getenv("KRB5_KTNAME"):
        click.echo("Kerberos keytab not specified, set environment variable 'KRB5_KTNAME'", err=True)
        exit(250)

    try:
        principal = kerberos.getServerPrincipalDetails("HTTP", FQDN)
    except kerberos.KrbError as exc:
        click.echo("Failed to initialize Kerberos, reason: %s" % exc, err=True)
        exit(249)
    else:
        click.echo("Kerberos enabled, service principal is HTTP/%s" % FQDN)
else:
    NotImplemented

def login_required(func):
    def pam_authenticate(resource, req, resp, *args, **kwargs):
        """
        Authenticate against PAM with WWW Basic Auth credentials
        """
        authorization = req.get_header("Authorization")
        if not authorization:
            resp.append_header("WWW-Authenticate", "Basic")
            raise falcon.HTTPUnauthorized("Forbidden", "Please authenticate")

        if not authorization.startswith("Basic "):
            raise falcon.HTTPForbidden("Forbidden", "Bad header: %s" % authorization)

        from base64 import b64decode
        basic, token = authorization.split(" ", 1)
        user, passwd = b64decode(token).split(":", 1)

        import simplepam
        if not simplepam.authenticate(user, passwd, "sshd"):
            raise falcon.HTTPForbidden("Forbidden", "Invalid password")

        req.context["user"] = user
        return func(resource, req, resp, *args, **kwargs)


    def kerberos_authenticate(resource, req, resp, *args, **kwargs):
        authorization = req.get_header("Authorization")

        if not authorization:
            resp.append_header("WWW-Authenticate", "Negotiate")
            logger.debug("No Kerberos ticket offered while attempting to access %s from %s", req.env["PATH_INFO"], req.env["REMOTE_ADDR"])
            raise falcon.HTTPUnauthorized("Unauthorized", "No Kerberos ticket offered, are you sure you've logged in with domain user account?")

        token = ''.join(authorization.split()[1:])

        try:
            result, context = kerberos.authGSSServerInit("HTTP@" + FQDN)
        except kerberos.GSSError as ex:
            # TODO: logger.error
            raise falcon.HTTPForbidden("Forbidden", "Authentication System Failure: %s(%s)" % (ex.args[0][0], ex.args[1][0],))

        try:
            result = kerberos.authGSSServerStep(context, token)
        except kerberos.GSSError as ex:
            s = str(dir(ex))
            kerberos.authGSSServerClean(context)
            # TODO: logger.error
            raise falcon.HTTPForbidden("Forbidden", "Bad credentials: %s (%s)" % (ex.args[0][0], ex.args[1][0]))
        except kerberos.KrbError as ex:
            kerberos.authGSSServerClean(context)
            # TODO: logger.error
            raise falcon.HTTPForbidden("Forbidden", "Bad credentials: %s" % (ex.args[0],))

        user = kerberos.authGSSServerUserName(context)
        req.context["user"], req.context["user_realm"] = user.split("@")

        try:
            # BUGBUG: https://github.com/02strich/pykerberos/issues/6
            #kerberos.authGSSServerClean(context)
            pass
        except kerberos.GSSError as ex:
            # TODO: logger.error
            raise error.LoginFailed('Authentication System Failure %s(%s)' % (ex.args[0][0], ex.args[1][0],))

        if result == kerberos.AUTH_GSS_COMPLETE:
            logger.debug("Succesfully authenticated user %s for %s from %s", req.context["user"], req.env["PATH_INFO"], req.env["REMOTE_ADDR"])
            return func(resource, req, resp, *args, **kwargs)
        elif result == kerberos.AUTH_GSS_CONTINUE:
            # TODO: logger.error
            raise falcon.HTTPUnauthorized("Unauthorized", "Tried GSSAPI")
        else:
            # TODO: logger.error
            raise falcon.HTTPForbidden("Forbidden", "Tried GSSAPI")

    if config.AUTHENTICATION_BACKEND == "kerberos":
        return kerberos_authenticate
    elif config.AUTHENTICATION_BACKEND == "pam":
        return pam_authenticate
    else:
        NotImplemented


def authorize_admin(func):
    def wrapped(self, req, resp, *args, **kwargs):
        from certidude import config
        # Parse remote IPv4/IPv6 address
        remote_addr = ipaddress.ip_network(req.env["REMOTE_ADDR"].decode("utf-8"))

        # Check for administration subnet whitelist
        print("Comparing:", config.ADMIN_SUBNETS, "To:", remote_addr)
        for subnet in config.ADMIN_SUBNETS:
            if subnet.overlaps(remote_addr):
                break
        else:
            logger.info("Rejected access to administrative call %s by %s from %s, source address not whitelisted", req.env["PATH_INFO"], req.context["user"], remote_addr)
            raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % remote_addr)

        # Check for username whitelist
        if req.context.get("user") not in config.ADMIN_USERS:
            logger.info("Rejected access to administrative call %s by %s from %s, user not whitelisted", req.env["PATH_INFO"], req.context["user"], remote_addr)
            raise falcon.HTTPForbidden("Forbidden", "User %s not whitelisted" % req.context.get("user"))

        # Retain username, TODO: Better abstraction with username, e-mail, sn, gn?

        return func(self, req, resp, *args, **kwargs)
    return wrapped
