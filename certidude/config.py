import configparser
import ipaddress
import os
from certidude import const
from certidude.profile import SignatureProfile
from collections import OrderedDict
from datetime import timedelta

# Options that are parsed from config file are fetched here

cp = configparser.RawConfigParser()
cp.readfp(open(const.SERVER_CONFIG_PATH, "r"))

AUTHENTICATION_BACKENDS = set([j for j in
    cp.get("authentication", "backends").split(" ") if j])   # kerberos, pam, ldap
AUTHORIZATION_BACKEND = cp.get("authorization", "backend")  # whitelist, ldap, posix
ACCOUNTS_BACKEND = cp.get("accounts", "backend")             # posix, ldap
MAIL_SUFFIX = cp.get("accounts", "mail suffix")

KERBEROS_KEYTAB = cp.get("authentication", "kerberos keytab")
KERBEROS_REALM = cp.get("authentication", "kerberos realm")
LDAP_AUTHENTICATION_URI = cp.get("authentication", "ldap uri")
LDAP_GSSAPI_CRED_CACHE = cp.get("accounts", "ldap gssapi credential cache")
LDAP_ACCOUNTS_URI = cp.get("accounts", "ldap uri")
LDAP_BASE = cp.get("accounts", "ldap base")
LDAP_MAIL_ATTRIBUTE = cp.get("accounts", "ldap mail attribute")

USER_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "user subnets").split(" ") if j])
ADMIN_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "admin subnets").split(" ") if j])
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
RENEWAL_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "renewal subnets").split(" ") if j])
OVERWRITE_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "overwrite subnets").split(" ") if j])
MACHINE_ENROLLMENT_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "machine enrollment subnets").split(" ") if j])
KERBEROS_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "kerberos subnets").split(" ") if j])

AUTHORITY_DIR = "/var/lib/certidude"
AUTHORITY_PRIVATE_KEY_PATH = cp.get("authority", "private key path")
AUTHORITY_CERTIFICATE_PATH = cp.get("authority", "certificate path")
SELF_KEY_PATH = cp.get("authority", "self key path")
REQUESTS_DIR = cp.get("authority", "requests dir")
SIGNED_DIR = cp.get("authority", "signed dir")
SIGNED_BY_SERIAL_DIR = os.path.join(SIGNED_DIR, "by-serial")
REVOKED_DIR = cp.get("authority", "revoked dir")
EXPIRED_DIR = cp.get("authority", "expired dir")

MAILER_NAME = cp.get("mailer", "name")
MAILER_ADDRESS = cp.get("mailer", "address")

BOOTSTRAP_TEMPLATE = cp.get("bootstrap", "services template")

USER_ENROLLMENT_ALLOWED = {
    "forbidden": False, "single allowed": True, "multiple allowed": True }[
    cp.get("authority", "user enrollment")]
USER_MULTIPLE_CERTIFICATES = {
    "forbidden": False, "single allowed": False, "multiple allowed": True }[
    cp.get("authority", "user enrollment")]

REQUEST_SUBMISSION_ALLOWED = cp.getboolean("authority", "request submission allowed")
AUTHORITY_CERTIFICATE_URL = cp.get("signature", "authority certificate url")
AUTHORITY_CRL_URL = "http://%s/api/revoked" % const.FQDN

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
LDAP_COMPUTER_FILTER = cp.get("authorization", "ldap computer filter")

if "%s" not in LDAP_USER_FILTER: raise ValueError("No placeholder %s for username in 'ldap user filter'")
if "%s" not in LDAP_ADMIN_FILTER: raise ValueError("No placeholder %s for username in 'ldap admin filter'")

TAG_TYPES = [j.split("/", 1) + [cp.get("tagging", j)] for j in cp.options("tagging")]

# Tokens
TOKEN_URL = cp.get("token", "url")
TOKEN_BACKEND = cp.get("token", "backend")
TOKEN_LIFETIME = timedelta(minutes=cp.getint("token", "lifetime")) # Convert minutes to seconds
TOKEN_DATABASE = cp.get("token", "database")
# TODO: Check if we don't have base or servers

# The API call for looking up scripts uses following directory as root
SCRIPT_DIR = cp.get("script", "path")

from configparser import ConfigParser
profile_config = ConfigParser()
profile_config.readfp(open(const.PROFILE_CONFIG_PATH))

PROFILES = dict([(key, SignatureProfile(key,
    profile_config.get(key, "title"),
    profile_config.get(key, "ou"),
    profile_config.getboolean(key, "ca"),
    profile_config.getint(key, "lifetime"),
    profile_config.get(key, "key usage"),
    profile_config.get(key, "extended key usage"),
    profile_config.get(key, "common name"),
    profile_config.get(key,  "revoked url"),
    profile_config.get(key, "responder url")
)) for key in profile_config.sections() if profile_config.getboolean(key, "enabled")])

cp2 = configparser.RawConfigParser()
cp2.readfp(open(const.BUILDER_CONFIG_PATH, "r"))
IMAGE_BUILDER_PROFILES = [(j, cp2.get(j, "title"), cp2.get(j, "rename")) for j in cp2.sections() if cp2.getboolean(j, "enabled")]

TOKEN_OVERWRITE_PERMITTED=True

SERVICE_PROTOCOLS = set([j.lower() for j in cp.get("service", "protocols").split(" ") if j])
SERVICE_ROUTERS = cp.get("service", "routers")
