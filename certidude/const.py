
import click
import os
import socket
import sys

KEY_SIZE = 1024 if os.getenv("TRAVIS") else 4096
RUN_DIR = "/run/certidude"
CONFIG_DIR = "/etc/certidude"
CONFIG_PATH = os.path.join(CONFIG_DIR, "server.conf")
CLIENT_CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")
SERVICES_CONFIG_PATH = os.path.join(CONFIG_DIR, "services.conf")
SERVER_PID_PATH = os.path.join(RUN_DIR, "server.pid")
SERVER_LOG_PATH = "/var/log/certidude-server.log"
SIGNER_SOCKET_PATH = "/run/certidude/signer.sock"
SIGNER_PID_PATH = os.path.join(RUN_DIR, "signer.pid")
SIGNER_LOG_PATH = "/var/log/certidude-signer.log"
STORAGE_PATH = "/var/lib/certidude/"

try:
    FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]
except socket.gaierror:
    FQDN = socket.gethostname()

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
