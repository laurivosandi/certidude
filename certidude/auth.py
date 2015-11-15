
import click
import falcon
import kerberos
import os
import re
import socket

# Vanilla Kerberos provides only username.
# AD also embeds PAC (Privilege Attribute Certificate), which
# is supposed to be sent via HTTP headers and it contains
# the groups user is part of.
# Even then we would have to manually look up the e-mail
# address eg via LDAP, hence to keep things simple
# we simply use Kerberos to authenticate.

FQDN = socket.getaddrinfo(socket.gethostname(), 0, flags=socket.AI_CANONNAME)[0][3]

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

def login_required(func):
    def wrapped(resource, req, resp, *args, **kwargs):
        authorization = req.get_header("Authorization")

        if not authorization:
            resp.append_header("WWW-Authenticate", "Negotiate")
            raise falcon.HTTPUnauthorized("Unauthorized", "No Kerberos ticket offered, are you sure you've logged in with domain user account?")

        token = ''.join(authorization.split()[1:])

        try:
            result, context = kerberos.authGSSServerInit("HTTP@" + FQDN)
        except kerberos.GSSError as ex:
            raise falcon.HTTPForbidden("Forbidden", "Authentication System Failure: %s(%s)" % (ex.args[0][0], ex.args[1][0],))

        try:
            result = kerberos.authGSSServerStep(context, token)
        except kerberos.GSSError as ex:
            s = str(dir(ex))
            kerberos.authGSSServerClean(context)
            raise falcon.HTTPForbidden("Forbidden", "Bad credentials: %s (%s)" % (ex.args[0][0], ex.args[1][0]))
        except kerberos.KrbError as ex:
            kerberos.authGSSServerClean(context)
            raise falcon.HTTPForbidden("Forbidden", "Bad credentials: %s" % (ex.args[0],))

        req.context["user"] = kerberos.authGSSServerUserName(context).split("@")

        try:
            # BUGBUG: https://github.com/02strich/pykerberos/issues/6
            #kerberos.authGSSServerClean(context)
            pass
        except kerberos.GSSError as ex:
            raise error.LoginFailed('Authentication System Failure %s(%s)' % (ex.args[0][0], ex.args[1][0],))

        if result == kerberos.AUTH_GSS_COMPLETE:
            return func(resource, req, resp, *args, **kwargs)
        elif result == kerberos.AUTH_GSS_CONTINUE:
            raise falcon.HTTPUnauthorized("Unauthorized", "Tried GSSAPI")
        else:
            raise falcon.HTTPForbidden("Forbidden", "Tried GSSAPI")

    return wrapped
