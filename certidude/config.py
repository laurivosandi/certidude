
import click
import codecs
import configparser
import ipaddress
import os
import string
from random import choice
from urllib.parse import urlparse

cp = configparser.ConfigParser()
cp.readfp(codecs.open("/etc/certidude/server.conf", "r", "utf8"))

AUTHENTICATION_BACKENDS = set([j for j in
    cp.get("authentication", "backends").split(" ") if j])   # kerberos, pam, ldap
AUTHORIZATION_BACKEND = cp.get("authorization", "backend")  # whitelist, ldap, posix
ACCOUNTS_BACKEND = cp.get("accounts", "backend")             # posix, ldap

USER_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "user subnets").split(" ") if j])
ADMIN_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "admin subnets").split(" ") if j]).union(USER_SUBNETS)
AUTOSIGN_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "autosign subnets").split(" ") if j])
REQUEST_SUBNETS = set([ipaddress.ip_network(j) for j in
    cp.get("authorization", "request subnets").split(" ") if j]).union(AUTOSIGN_SUBNETS)

SIGNER_SOCKET_PATH = "/run/certidude/signer.sock"
SIGNER_PID_PATH = "/run/certidude/signer.pid"

AUTHORITY_DIR = "/var/lib/certidude"
AUTHORITY_PRIVATE_KEY_PATH = cp.get("authority", "private key path")
AUTHORITY_CERTIFICATE_PATH = cp.get("authority", "certificate path")
REQUESTS_DIR = cp.get("authority", "requests dir")
SIGNED_DIR = cp.get("authority", "signed dir")
REVOKED_DIR = cp.get("authority", "revoked dir")
OUTBOX = cp.get("authority", "outbox")

CERTIFICATE_BASIC_CONSTRAINTS = "CA:FALSE"
CERTIFICATE_KEY_USAGE_FLAGS = "digitalSignature,keyEncipherment"
CERTIFICATE_EXTENDED_KEY_USAGE_FLAGS = "clientAuth"
CERTIFICATE_LIFETIME = int(cp.get("signature", "certificate lifetime"))

REVOCATION_LIST_LIFETIME = int(cp.get("signature", "revocation list lifetime"))

PUSH_TOKEN = "".join([choice(string.ascii_letters + string.digits) for j in range(0,32)])

PUSH_TOKEN = "ca"

try:
    PUSH_EVENT_SOURCE = cp.get("push", "event source")
    PUSH_LONG_POLL = cp.get("push", "long poll")
    PUSH_PUBLISH = cp.get("push", "publish")
except configparser.NoOptionError:
    PUSH_SERVER = cp.get("push", "server") or "http://localhost"
    PUSH_EVENT_SOURCE = PUSH_SERVER + "/ev/%s"
    PUSH_LONG_POLL = PUSH_SERVER + "/lp/%s"
    PUSH_PUBLISH = PUSH_SERVER + "/pub?id=%s"


TAGGING_BACKEND = cp.get("tagging", "backend")
LOGGING_BACKEND = cp.get("logging", "backend")
LEASES_BACKEND = cp.get("leases", "backend")


if "whitelist" == AUTHORIZATION_BACKEND:
    USERS_WHITELIST = set([j for j in  cp.get("authorization", "users whitelist").split(" ") if j])
    ADMINS_WHITELIST = set([j for j in  cp.get("authorization", "admins whitelist").split(" ") if j])
elif "posix" == AUTHORIZATION_BACKEND:
    USERS_GROUP = cp.get("authorization", "posix user group")
    ADMINS_GROUP = cp.get("authorization", "posix admin group")
elif "ldap" == AUTHORIZATION_BACKEND:
    USERS_GROUP = cp.get("authorization", "ldap user group")
    ADMINS_GROUP = cp.get("authorization", "ldap admin group")
else:
    raise NotImplementedError("Unknown authorization backend '%s'" % AUTHORIZATION_BACKEND)

LDAP_USER_FILTER = cp.get("authorization", "ldap user filter")
LDAP_GROUP_FILTER = cp.get("authorization", "ldap group filter")
LDAP_MEMBERS_FILTER = cp.get("authorization", "ldap members filter")
LDAP_MEMBER_OF_FILTER = cp.get("authorization", "ldap member of filter")

for line in open("/etc/ldap/ldap.conf"):
    line = line.strip().lower()
    if "#" in line:
        line, _ = line.split("#", 1)
    if not " " in line:
        continue
    key, value = line.split(" ", 1)
    if key == "uri":
        LDAP_SERVERS = set([j for j in value.split(" ") if j])
        click.echo("LDAP servers: %s" % " ".join(LDAP_SERVERS))
    elif key == "base":
        LDAP_BASE = value
else:
    click.echo("No LDAP servers specified in /etc/ldap/ldap.conf")

