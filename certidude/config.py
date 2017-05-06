
import click
import codecs
import configparser
import ipaddress
import os
import string
import const
from random import choice

# Options that are parsed from config file are fetched here

cp = configparser.RawConfigParser()
cp.readfp(codecs.open(const.CONFIG_PATH, "r", "utf8"))

AUTHENTICATION_BACKENDS = set([j for j in
    cp.get("authentication", "backends").split(" ") if j])   # kerberos, pam, ldap
AUTHORIZATION_BACKEND = cp.get("authorization", "backend")  # whitelist, ldap, posix
ACCOUNTS_BACKEND = cp.get("accounts", "backend")             # posix, ldap

KERBEROS_KEYTAB = cp.get("authentication", "kerberos keytab")
LDAP_AUTHENTICATION_URI = cp.get("authentication", "ldap uri")
LDAP_GSSAPI_CRED_CACHE = cp.get("accounts", "ldap gssapi credential cache")
LDAP_ACCOUNTS_URI = cp.get("accounts", "ldap uri")
LDAP_BASE = cp.get("accounts", "ldap base")

USER_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "user subnets").split(" ") if j])
ADMIN_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "admin subnets").split(" ") if j]).union(USER_SUBNETS)
AUTOSIGN_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "autosign subnets").split(" ") if j])
REQUEST_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "request subnets").split(" ") if j]).union(AUTOSIGN_SUBNETS)

AUTHORITY_DIR = "/var/lib/certidude"
AUTHORITY_PRIVATE_KEY_PATH = cp.get("authority", "private key path")
AUTHORITY_CERTIFICATE_PATH = cp.get("authority", "certificate path")
REQUESTS_DIR = cp.get("authority", "requests dir")
SIGNED_DIR = cp.get("authority", "signed dir")
REVOKED_DIR = cp.get("authority", "revoked dir")
EXPIRED_DIR = cp.get("authority", "expired dir")

MAILER_NAME = cp.get("mailer", "name")
MAILER_ADDRESS = cp.get("mailer", "address")

BOOTSTRAP_TEMPLATE = cp.get("bootstrap", "services template")

MACHINE_ENROLLMENT_ALLOWED = {
    "forbidden": False, "allowed": True }[
    cp.get("authority", "machine enrollment")]
USER_ENROLLMENT_ALLOWED = {
    "forbidden": False, "single allowed": True, "multiple allowed": True }[
    cp.get("authority", "user enrollment")]
USER_MULTIPLE_CERTIFICATES = {
    "forbidden": False, "single allowed": False, "multiple allowed": True }[
    cp.get("authority", "user enrollment")]

REQUEST_SUBMISSION_ALLOWED = cp.getboolean("authority", "request submission allowed")
CLIENT_CERTIFICATE_LIFETIME = cp.getint("signature", "client certificate lifetime")
SERVER_CERTIFICATE_LIFETIME = cp.getint("signature", "server certificate lifetime")
AUTHORITY_CERTIFICATE_URL = cp.get("signature", "authority certificate url")
CERTIFICATE_CRL_URL = cp.get("signature", "revoked url")
CERTIFICATE_RENEWAL_ALLOWED = cp.getboolean("signature", "renewal allowed")

REVOCATION_LIST_LIFETIME = cp.getint("signature", "revocation list lifetime")

EVENT_SOURCE_TOKEN = cp.get("push", "event source token")
EVENT_SOURCE_PUBLISH = cp.get("push", "event source publish")
EVENT_SOURCE_SUBSCRIBE = cp.get("push", "event source subscribe")
LONG_POLL_PUBLISH = cp.get("push", "long poll publish")
LONG_POLL_SUBSCRIBE = cp.get("push", "long poll subscribe")

LOGGING_BACKEND = cp.get("logging", "backend")

if "whitelist" == AUTHORIZATION_BACKEND:
    USERS_WHITELIST = set([j for j in  cp.get("authorization", "users whitelist").split(" ") if j])
    ADMINS_WHITELIST = set([j for j in  cp.get("authorization", "admins whitelist").split(" ") if j])
elif "posix" == AUTHORIZATION_BACKEND:
    USERS_GROUP = cp.get("authorization", "posix user group")
    ADMIN_GROUP = cp.get("authorization", "posix admin group")
elif "ldap" == AUTHORIZATION_BACKEND:
    LDAP_USER_FILTER = cp.get("authorization", "ldap user filter")
    LDAP_ADMIN_FILTER = cp.get("authorization", "ldap admin filter")
    if "%s" not in LDAP_USER_FILTER: raise ValueError("No placeholder %s for username in 'ldap user filter'")
    if "%s" not in LDAP_ADMIN_FILTER: raise ValueError("No placeholder %s for username in 'ldap admin filter'")
else:
    raise NotImplementedError("Unknown authorization backend '%s'" % AUTHORIZATION_BACKEND)

TAG_TYPES = [j.split("/", 1) + [cp.get("tagging", j)] for j in cp.options("tagging")]

# Tokens
BUNDLE_FORMAT = cp.get("token", "format")
OPENVPN_PROFILE_TEMPLATE = cp.get("token", "openvpn profile template")
TOKEN_URL = cp.get("token", "url")
TOKEN_LIFETIME = cp.getint("token", "lifetime") * 60 # Convert minutes to seconds
TOKEN_SECRET = cp.get("token", "secret")

# TODO: Check if we don't have base or servers

# The API call for looking up scripts uses following directory as root
SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "templates", "script")
SCRIPT_DEFAULT = "openwrt.sh"
