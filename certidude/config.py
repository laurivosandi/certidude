
import click
import codecs
import configparser
import ipaddress
import os
import socket
import string
from random import choice
from urllib.parse import urlparse

FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]

cp = configparser.ConfigParser()
cp.readfp(codecs.open("/etc/certidude/server.conf", "r", "utf8"))

AUTHENTICATION_BACKEND = cp.get("authentication", "backend") # kerberos, pam
AUTHORIZATION_BACKEND = cp.get("authorization", "backend") # whitelist, ldap, pam

ADMIN_USERS = set([j for j in  cp.get("authorization", "admin_users").split(" ") if j])
ADMIN_SUBNETS = set([ipaddress.ip_network(j) for j in cp.get("authorization", "admin_subnets").split(" ") if j])
AUTOSIGN_SUBNETS = set([ipaddress.ip_network(j) for j in cp.get("authorization", "autosign_subnets").split(" ") if j])
REQUEST_SUBNETS = set([ipaddress.ip_network(j) for j in cp.get("authorization", "request_subnets").split(" ") if j]).union(AUTOSIGN_SUBNETS)

SIGNER_SOCKET_PATH = "/run/certidude/signer.sock"
SIGNER_PID_PATH = "/run/certidude/signer.pid"

AUTHORITY_DIR = "/var/lib/certidude"
AUTHORITY_PRIVATE_KEY_PATH = cp.get("authority", "private_key_path")
AUTHORITY_CERTIFICATE_PATH = cp.get("authority", "certificate_path")
REQUESTS_DIR = cp.get("authority", "requests_dir")
SIGNED_DIR = cp.get("authority", "signed_dir")
REVOKED_DIR = cp.get("authority", "revoked_dir")

#LOG_DATA = cp.get("logging", "database")

CERTIFICATE_BASIC_CONSTRAINTS = "CA:FALSE"
CERTIFICATE_KEY_USAGE_FLAGS = "nonRepudiation,digitalSignature,keyEncipherment"
CERTIFICATE_EXTENDED_KEY_USAGE_FLAGS = "clientAuth"
CERTIFICATE_LIFETIME = int(cp.get("signature", "certificate_lifetime"))

REVOCATION_LIST_LIFETIME = int(cp.get("signature", "revocation_list_lifetime"))

PUSH_TOKEN = "".join([choice(string.ascii_letters + string.digits) for j in range(0,32)])

PUSH_TOKEN = "ca"

try:
    PUSH_EVENT_SOURCE = cp.get("push", "event_source")
    PUSH_LONG_POLL = cp.get("push", "long_poll")
    PUSH_PUBLISH = cp.get("push", "publish")
except configparser.NoOptionError:
    PUSH_SERVER = cp.get("push", "server") or "http://localhost"
    PUSH_EVENT_SOURCE = PUSH_SERVER + "/ev/%s"
    PUSH_LONG_POLL = PUSH_SERVER + "/lp/%s"
    PUSH_PUBLISH = PUSH_SERVER + "/pub?id=%s"

o = urlparse(cp.get("authority", "database") if cp.has_option("authority", "database") else "")

if not o.scheme:
    DATABASE_POOL = None
elif o.scheme == "mysql":
    import mysql.connector
    DATABASE_POOL = mysql.connector.pooling.MySQLConnectionPool(
        pool_size = 32,
        user=o.username,
        password=o.password,
        host=o.hostname,
        database=o.path[1:])
else:
    raise NotImplementedError("Unsupported database scheme %s, currently only mysql://user:pass@host/database is supported" % o.scheme)

