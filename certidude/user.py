
import click
import grp
import os
import pwd
from certidude import const, config

class User(object):
    def __init__(self, username, mail, given_name="", surname=""):
        self.name = username
        self.mail = mail
        self.given_name = given_name
        self.surname = surname

    def __unicode__(self):
        if self.given_name and self.surname:
            return u"%s %s <%s>" % (self.given_name, self.surname, self.mail)
        else:
            return self.mail

    def __hash__(self):
        return hash(self.mail)

    def __eq__(self, other):
        assert isinstance(other, User), "%s is not instance of User" % repr(other)
        return self.mail == other.mail

    def __repr__(self):
        return unicode(self).encode("utf-8")

    def is_admin(self):
        if not hasattr(self, "_is_admin"):
            self._is_admin = self.objects.is_admin(self)
        return self._is_admin

    class DoesNotExist(StandardError):
        pass


class PosixUserManager(object):
    def get(self, username):
        _, _, _, _, gecos, _, _ = pwd.getpwnam(username)
        gecos = gecos.decode("utf-8").split(",")
        full_name = gecos[0]
        mail = u"%s@%s" % (username, const.DOMAIN)
        if full_name and " " in full_name:
            given_name, surname = full_name.split(" ", 1)
            return User(username, mail, given_name, surname)
        return User(username, mail)

    def filter_admins(self):
        _, _, gid, members = grp.getgrnam(config.ADMIN_GROUP)
        for username in members:
            yield self.get(username)

    def is_admin(self, user):
        import grp
        _, _, gid, members = grp.getgrnam(config.ADMIN_GROUP)
        return user.name in members

    def all(self):
        _, _, gid, members = grp.getgrnam(config.USERS_GROUP)
        for username in members:
            yield self.get(username)
        for user in self.filter_admins(): # TODO: dedup
            yield user


class DirectoryConnection(object):
    def __enter__(self):
        import ldap
        import ldap.sasl

        # TODO: Implement simple bind
        if not os.path.exists(config.LDAP_GSSAPI_CRED_CACHE):
            raise ValueError("Ticket cache at %s not initialized, unable to "
                "authenticate with computer account against LDAP server!" % config.LDAP_GSSAPI_CRED_CACHE)
        os.environ["KRB5CCNAME"] = config.LDAP_GSSAPI_CRED_CACHE
        self.conn = ldap.initialize(config.LDAP_ACCOUNTS_URI)
        self.conn.set_option(ldap.OPT_REFERRALS, 0)
        click.echo("Connecing to %s using Kerberos ticket cache from %s" %
            (config.LDAP_ACCOUNTS_URI, config.LDAP_GSSAPI_CRED_CACHE))
        self.conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())
        return self.conn

    def __exit__(self, type, value, traceback):
        self.conn.unbind_s()


class ActiveDirectoryUserManager(object):
    def get(self, username):
        # TODO: Sanitize username
        with DirectoryConnection() as conn:
            ft = config.LDAP_USER_FILTER % username
            attribs = "cn", "givenName", "sn", "mail", "userPrincipalName"
            r = conn.search_s(config.LDAP_BASE, 2, ft.encode("utf-8"), attribs)
            for dn, entry in r:
                if not dn:
                    continue
                if entry.get("givenname") and entry.get("sn"):
                    given_name, = entry.get("givenName")
                    surname, = entry.get("sn")
                else:
                    cn, = entry.get("cn")
                    if " " in cn:
                        given_name, surname = cn.split(" ", 1)
                    else:
                        given_name, surname = cn, ""

                mail, = entry.get("mail") or entry.get("userPrincipalName") or (username + "@" + const.DOMAIN,)
                return User(username.decode("utf-8"), mail.decode("utf-8"),
                    given_name.decode("utf-8"), surname.decode("utf-8"))
            raise User.DoesNotExist("User %s does not exist" % username)

    def filter(self, ft):
        with DirectoryConnection() as conn:
            attribs = "givenName", "surname", "samaccountname", "cn", "mail", "userPrincipalName"
            r = conn.search_s(config.LDAP_BASE, 2, ft.encode("utf-8"), attribs)
            for dn,entry in r:
                if not dn:
                    continue
                username, = entry.get("sAMAccountName")
                cn, = entry.get("cn")
                mail, = entry.get("mail") or entry.get("userPrincipalName") or (username + "@" + const.DOMAIN,)
                if entry.get("givenName") and entry.get("sn"):
                    given_name, = entry.get("givenName")
                    surname, = entry.get("sn")
                else:
                    cn, = entry.get("cn")
                    if " " in cn:
                        given_name, surname = cn.split(" ", 1)
                    else:
                        given_name, surname = cn, ""
                yield User(username.decode("utf-8"), mail.decode("utf-8"),
                    given_name.decode("utf-8"), surname.decode("utf-8"))

    def filter_admins(self):
        """
        Return admin User objects
        """
        return self.filter(config.LDAP_ADMIN_FILTER % "*")

    def all(self):
        """
        Return all valid User objects
        """
        return self.filter(ft=config.LDAP_USER_FILTER % "*")

    def is_admin(self, user):
        with DirectoryConnection() as conn:
            ft = config.LDAP_ADMIN_FILTER % user.name
            r = conn.search_s(config.LDAP_BASE, 2, ft.encode("utf-8"), ["cn"])
            for dn, entry in r:
                if not dn:
                    continue
                return True
            return False

if config.ACCOUNTS_BACKEND == "ldap":
    User.objects = ActiveDirectoryUserManager()
elif config.ACCOUNTS_BACKEND == "posix":
    User.objects = PosixUserManager()
else:
    raise NotImplementedError("Authorization backend %s not supported" % repr(config.AUTHORIZATION_BACKEND))

