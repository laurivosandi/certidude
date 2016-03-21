
import click
import falcon
import kerberos
import logging
import os
import re
import socket
from certidude.firewall import whitelist_subnets
from certidude import config, constants

logger = logging.getLogger("api")

FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]

if config.AUTHENTICATION_BACKENDS == {"kerberos"}:
    ktname = os.getenv("KRB5_KTNAME")

    if not ktname:
        click.echo("Kerberos keytab not specified, set environment variable 'KRB5_KTNAME'", err=True)
        exit(250)
    if not os.path.exists(ktname):
        click.echo("Kerberos keytab %s does not exist" % ktname, err=True)
        exit(248)

    try:
        principal = kerberos.getServerPrincipalDetails("HTTP", FQDN)
    except kerberos.KrbError as exc:
        click.echo("Failed to initialize Kerberos, service principal is HTTP/%s, reason: %s" % (FQDN, exc), err=True)
        exit(249)
    else:
        click.echo("Kerberos enabled, service principal is HTTP/%s" % FQDN)


class User(object):
    def __init__(self, name):
        if "@" in name:
            self.mail = name
            self.name, self.domain = name.split("@")
        else:
            self.mail = None
            self.name, self.domain = name, None
        self.given_name, self.surname = None, None

    def __repr__(self):
        if self.given_name and self.surname:
            return u"%s %s <%s>" % (self.given_name, self.surname, self.mail)
        else:
            return self.mail


def member_of(group_name):
    """
    Check if requesting user is member of an UNIX group
    """

    def wrapper(func):
        def posix_check_group_membership(resource, req, resp, *args, **kwargs):
            import grp
            _, _, gid, members = grp.getgrnam(group_name)
            if req.context.get("user").name not in members:
                logger.info("User '%s' not member of group '%s'", req.context.get("user").name, group_name)
                raise falcon.HTTPForbidden("Forbidden", "User not member of designated group")
            req.context.get("groups").add(group_name)
            return func(resource, req, resp, *args, **kwargs)

        def ldap_check_group_membership(resource, req, resp, *args, **kwargs):
            import ldap

            ft = config.LDAP_MEMBERS_FILTER % (group_name, req.context.get("user").dn)
            r = req.context.get("ldap_conn").search_s(config.LDAP_BASE, ldap.SCOPE_SUBTREE,
                ft.encode("utf-8"),
                ["member"])

            for dn,entry in r:
                if not dn: continue
                logger.debug("User %s is member of group %s" % (
                    req.context.get("user"), repr(group_name)))
                req.context.get("groups").add(group_name)
                break
            else:
                raise ValueError("Failed to look up group '%s' with '%s' listed as member in LDAP" % (group_name, req.context.get("user").name))

            return func(resource, req, resp, *args, **kwargs)

        if config.AUTHORIZATION_BACKEND == "ldap":
            return ldap_check_group_membership
        elif config.AUTHORIZATION_BACKEND == "posix":
            return posix_check_group_membership
        else:
            raise NotImplementedError("Authorization backend %s not supported" % config.AUTHORIZATION_BACKEND)
    return wrapper


def account_info(func):
    # TODO: Use Privilege Account Certificate for Kerberos

    def posix_account_info(resource, req, resp, *args, **kwargs):
        import pwd
        _, _, _, _, gecos, _, _ = pwd.getpwnam(req.context["user"].name)
        gecos = gecos.decode("utf-8").split(",")
        full_name = gecos[0]
        if full_name and " " in full_name:
            req.context["user"].given_name, req.context["user"].surname = full_name.split(" ", 1)
        req.context["user"].mail = req.context["user"].name + "@" + constants.DOMAIN
        return func(resource, req, resp, *args, **kwargs)

    def ldap_account_info(resource, req, resp, *args, **kwargs):
        import ldap
        import ldap.sasl

        if "ldap_conn" not in req.context:
            for server in config.LDAP_SERVERS:
                conn = ldap.initialize(server)
                conn.set_option(ldap.OPT_REFERRALS, 0)
                if os.path.exists("/etc/krb5.keytab"):
                    ticket_cache = os.getenv("KRB5CCNAME")
                    if not ticket_cache:
                        raise ValueError("Ticket cache not initialized, unable to authenticate with computer account against LDAP server!")
                    click.echo("Connecing to %s using Kerberos ticket cache from %s" % (server, ticket_cache))
                    conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())
                else:
                    raise NotImplementedError("LDAP simple bind not supported, use Kerberos")
                req.context["ldap_conn"] = conn
                break
            else:
                raise ValueError("No LDAP servers!")

        ft = config.LDAP_USER_FILTER % req.context.get("user").name
        r = req.context.get("ldap_conn").search_s(config.LDAP_BASE, ldap.SCOPE_SUBTREE,
            ft,
            ["cn", "givenname", "sn", "mail", "userPrincipalName"])

        for dn, entry in r:
            if not dn: continue
            if entry.get("givenname") and entry.get("sn"):
                given_name, = entry.get("givenName")
                surname, = entry.get("sn")
                req.context["user"].given_name = given_name.decode("utf-8")
                req.context["user"].surname = surname.decode("utf-8")
            else:
                cn, = entry.get("cn")
                if " " in cn:
                    req.context["user"].given_name, req.context["user"].surname = cn.decode("utf-8").split(" ", 1)

            req.context["user"].dn = dn.decode("utf-8")
            req.context["user"].mail, = entry.get("mail") or entry.get("userPrincipalName") or (None,)
            retval = func(resource, req, resp, *args, **kwargs)
            req.context.get("ldap_conn").unbind_s()
            return retval
        else:
            raise ValueError("Failed to look up %s in LDAP" % req.context.get("user"))

    if config.ACCOUNTS_BACKEND == "ldap":
        return ldap_account_info
    elif config.ACCOUNTS_BACKEND == "posix":
        return posix_account_info
    else:
        raise NotImplementedError("Accounts backend %s not supported" % config.ACCOUNTS_BACKEND)


def authenticate(optional=False):
    def wrapper(func):
        def kerberos_authenticate(resource, req, resp, *args, **kwargs):
            if optional and not req.get_param_as_bool("authenticate"):
                return func(resource, req, resp, *args, **kwargs)

            if not req.auth:
                resp.append_header("WWW-Authenticate", "Negotiate")
                logger.debug("No Kerberos ticket offered while attempting to access %s from %s",
                    req.env["PATH_INFO"], req.context.get("remote_addr"))
                raise falcon.HTTPUnauthorized("Unauthorized",
                    "No Kerberos ticket offered, are you sure you've logged in with domain user account?")

            token = ''.join(req.auth.split()[1:])

            try:
                result, context = kerberos.authGSSServerInit("HTTP@" + FQDN)
            except kerberos.GSSError as ex:
                # TODO: logger.error
                raise falcon.HTTPForbidden("Forbidden",
                    "Authentication System Failure: %s(%s)" % (ex.args[0][0], ex.args[1][0],))

            try:
                result = kerberos.authGSSServerStep(context, token)
            except kerberos.GSSError as ex:
                kerberos.authGSSServerClean(context)
                # TODO: logger.error
                raise falcon.HTTPForbidden("Forbidden",
                    "Bad credentials: %s (%d)" % (ex.args[0][0], ex.args[0][1]))
            except kerberos.KrbError as ex:
                kerberos.authGSSServerClean(context)
                # TODO: logger.error
                raise falcon.HTTPForbidden("Forbidden",
                    "Bad credentials: %s" % (ex.args[0],))

            user = kerberos.authGSSServerUserName(context)
            req.context["user"] = User(user)
            req.context["groups"] = set()

            try:
                kerberos.authGSSServerClean(context)
            except kerberos.GSSError as ex:
                # TODO: logger.error
                raise falcon.HTTPUnauthorized("Authentication System Failure %s (%s)" % (ex.args[0][0], ex.args[1][0]))

            if result == kerberos.AUTH_GSS_COMPLETE:
                logger.debug("Succesfully authenticated user %s for %s from %s",
                    req.context["user"], req.env["PATH_INFO"], req.context["remote_addr"])
                return account_info(func)(resource, req, resp, *args, **kwargs)
            elif result == kerberos.AUTH_GSS_CONTINUE:
                # TODO: logger.error
                raise falcon.HTTPUnauthorized("Unauthorized", "Tried GSSAPI")
            else:
                # TODO: logger.error
                raise falcon.HTTPForbidden("Forbidden", "Tried GSSAPI")


        def ldap_authenticate(resource, req, resp, *args, **kwargs):
            """
            Authenticate against LDAP with WWW Basic Auth credentials
            """

            if optional and not req.get_param_as_bool("authenticate"):
                return func(resource, req, resp, *args, **kwargs)

            import ldap

            if not req.auth:
                resp.append_header("WWW-Authenticate", "Basic")
                raise falcon.HTTPUnauthorized("Forbidden",
                    "Please authenticate with %s domain account or supply UPN" % constants.DOMAIN)

            if not req.auth.startswith("Basic "):
                raise falcon.HTTPForbidden("Forbidden", "Bad header: %s" % req.auth)

            from base64 import b64decode
            basic, token = req.auth.split(" ", 1)
            user, passwd = b64decode(token).split(":", 1)

            if "ldap_conn" not in req.context:
                for server in config.LDAP_SERVERS:
                    click.echo("Connecting to %s as %s" % (server, user))
                    conn = ldap.initialize(server)
                    conn.set_option(ldap.OPT_REFERRALS, 0)
                    try:
                        conn.simple_bind_s(user if "@" in user else "%s@%s" % (user, constants.DOMAIN), passwd)
                    except ldap.LDAPError, e:
                        resp.append_header("WWW-Authenticate", "Basic")
                        logger.debug("Failed to authenticate with user '%s'", user)
                        raise falcon.HTTPUnauthorized("Forbidden",
                            "Please authenticate with %s domain account or supply UPN" % constants.DOMAIN)

                    req.context["ldap_conn"] = conn
                    break
                else:
                    raise ValueError("No LDAP servers!")

            req.context["user"] = User(user)
            req.context["groups"] = set()
            return account_info(func)(resource, req, resp, *args, **kwargs)


        def pam_authenticate(resource, req, resp, *args, **kwargs):
            """
            Authenticate against PAM with WWW Basic Auth credentials
            """

            if optional and not req.get_param_as_bool("authenticate"):
                return func(resource, req, resp, *args, **kwargs)

            if not req.auth:
                resp.append_header("WWW-Authenticate", "Basic")
                raise falcon.HTTPUnauthorized("Forbidden", "Please authenticate")

            if not req.auth.startswith("Basic "):
                raise falcon.HTTPForbidden("Forbidden", "Bad header: %s" % req.auth)

            from base64 import b64decode
            basic, token = req.auth.split(" ", 1)
            user, passwd = b64decode(token).split(":", 1)

            import simplepam
            if not simplepam.authenticate(user, passwd, "sshd"):
                raise falcon.HTTPUnauthorized("Forbidden", "Invalid password")

            req.context["user"] = User(user)
            req.context["groups"] = set()
            return account_info(func)(resource, req, resp, *args, **kwargs)

        if config.AUTHENTICATION_BACKENDS == {"kerberos"}:
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

    def whitelist_authorize(resource, req, resp, *args, **kwargs):
        # Check for username whitelist
        if not req.context.get("user") or req.context.get("user") not in config.ADMIN_WHITELIST:
            logger.info("Rejected access to administrative call %s by %s from %s, user not whitelisted",
                req.env["PATH_INFO"], req.context.get("user"), req.context.get("remote_addr"))
            raise falcon.HTTPForbidden("Forbidden", "User %s not whitelisted" % req.context.get("user"))
        return func(resource, req, resp, *args, **kwargs)

    if config.AUTHORIZATION_BACKEND == "whitelist":
        return whitelist_authorize
    else:
        return member_of(config.ADMINS_GROUP)(func)

