import configparser
import ipaddress
import os
from certidude import const
from collections import OrderedDict

# Options that are parsed from config file are fetched here

cp = configparser.RawConfigParser()
cp.readfp(open(const.SERVER_CONFIG_PATH, "r"))

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
SCEP_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "scep subnets").split(" ") if j])
OCSP_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "ocsp subnets").split(" ") if j])
CRL_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "crl subnets").split(" ") if j])

AUTHORITY_DIR = "/var/lib/certidude"
AUTHORITY_PRIVATE_KEY_PATH = cp.get("authority", "private key path")
AUTHORITY_CERTIFICATE_PATH = cp.get("authority", "certificate path")
REQUESTS_DIR = cp.get("authority", "requests dir")
SIGNED_DIR = cp.get("authority", "signed dir")
SIGNED_BY_SERIAL_DIR = os.path.join(SIGNED_DIR, "by-serial")
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
AUTHORITY_CERTIFICATE_URL = cp.get("signature", "authority certificate url")
AUTHORITY_CRL_URL = cp.get("signature", "revoked url")
AUTHORITY_OCSP_URL = cp.get("signature", "responder url")
CERTIFICATE_RENEWAL_ALLOWED = cp.getboolean("signature", "renewal allowed")

REVOCATION_LIST_LIFETIME = cp.getint("signature", "revocation list lifetime")

EVENT_SOURCE_TOKEN = cp.get("push", "event source token")
EVENT_SOURCE_PUBLISH = cp.get("push", "event source publish")
EVENT_SOURCE_SUBSCRIBE = cp.get("push", "event source subscribe")
LONG_POLL_PUBLISH = cp.get("push", "long poll publish")
LONG_POLL_SUBSCRIBE = cp.get("push", "long poll subscribe")

LOGGING_BACKEND = cp.get("logging", "backend")

USERS_GROUP = cp.get("authorization", "posix user group")
ADMIN_GROUP = cp.get("authorization", "posix admin group")
LDAP_USER_FILTER = cp.get("authorization", "ldap user filter")
LDAP_ADMIN_FILTER = cp.get("authorization", "ldap admin filter")
if "%s" not in LDAP_USER_FILTER: raise ValueError("No placeholder %s for username in 'ldap user filter'")
if "%s" not in LDAP_ADMIN_FILTER: raise ValueError("No placeholder %s for username in 'ldap admin filter'")

TAG_TYPES = [j.split("/", 1) + [cp.get("tagging", j)] for j in cp.options("tagging")]

# Tokens
TOKEN_URL = cp.get("token", "url")
TOKEN_LIFETIME = cp.getint("token", "lifetime") * 60 # Convert minutes to seconds
TOKEN_SECRET = cp.get("token", "secret").encode("ascii")

# TODO: Check if we don't have base or servers

# The API call for looking up scripts uses following directory as root
SCRIPT_DIR = cp.get("script", "path")

PROFILES = OrderedDict([[i, [j.strip() for j in cp.get("profile", i).split(",")]] for i in cp.options("profile")])

cp2 = configparser.RawConfigParser()
cp2.readfp(open(const.BUILDER_CONFIG_PATH, "r"))
IMAGE_BUILDER_PROFILES = [(j, cp2.get(j, "title"), cp2.get(j, "rename")) for j in cp2.sections()]
