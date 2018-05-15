
import click
import os
import socket
import sys
from datetime import timedelta

KEY_SIZE = 1024 if os.getenv("TRAVIS") else 4096
CURVE_NAME = "secp384r1"
RE_FQDN =  "^(([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])\.)+([a-z0-9]|[a-z0-9][a-z0-9\-_]*[a-z0-9])?$"
RE_HOSTNAME =  "^[a-z0-9]([a-z0-9\-_]{0,61}[a-z0-9])?$"
RE_COMMON_NAME = "^[A-Za-z0-9\-\.\_@]+$"
CLOCK_SKEW_TOLERANCE = timedelta(minutes=5) # Kerberos-like clock skew tolerance

RUN_DIR = "/run/certidude"
CONFIG_DIR = "/etc/certidude"
SERVER_CONFIG_PATH = os.path.join(CONFIG_DIR, "server.conf")
BUILDER_CONFIG_PATH = os.path.join(CONFIG_DIR, "builder.conf")
SCRIPT_DIR = os.path.join(CONFIG_DIR, "script")
BUILDER_SITE_SCRIPT = os.path.join(SCRIPT_DIR, "site.sh")
PROFILE_CONFIG_PATH = os.path.join(CONFIG_DIR, "profile.conf")
CLIENT_CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")
SERVICES_CONFIG_PATH = os.path.join(CONFIG_DIR, "services.conf")
SERVER_PID_PATH = os.path.join(RUN_DIR, "server.pid")
SERVER_LOG_PATH = "/var/log/certidude-server.log"
STORAGE_PATH = "/var/lib/certidude/"

try:
    FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]
except socket.gaierror:
    FQDN = socket.gethostname()
if hasattr(FQDN, "decode"): # Keep client backwards compatible with Python 2.x
    FQDN = FQDN.decode("ascii")

try:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
except ValueError: # If FQDN is not configured
    HOSTNAME = FQDN
    DOMAIN = None

# TODO: lazier, otherwise gets evaluated before installing package
if os.path.exists("/etc/strongswan/ipsec.conf"): # fedora dafuq?!
    STRONGSWAN_PREFIX = "/etc/strongswan"
else:
    STRONGSWAN_PREFIX = "/etc"
