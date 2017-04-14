
import click
import os
import socket
import sys

CONFIG_DIR = os.path.expanduser("~/.certidude") if os.getuid() else "/etc/certidude"
CONFIG_PATH = os.path.join(CONFIG_DIR, "server.conf")

CLIENT_CONFIG_PATH = os.path.join(CONFIG_DIR, "client.conf")
SERVICES_CONFIG_PATH = os.path.join(CONFIG_DIR, "services.conf")
SERVER_LOG_PATH = os.path.join(CONFIG_DIR, "server.log") if os.getuid() else "/var/log/certidude-server.log"
SIGNER_SOCKET_PATH = os.path.join(CONFIG_DIR, "signer.sock") if os.getuid() else "/run/certidude/signer.sock"
SIGNER_PID_PATH = os.path.join(CONFIG_DIR, "signer.pid") if os.getuid() else "/run/certidude/signer.pid"
SIGNER_LOG_PATH = os.path.join(CONFIG_DIR, "signer.log") if os.getuid() else "/var/log/certidude-signer.log"

# Work around the 'asn1 encoding routines:ASN1_mbstring_ncopy:string too long'
# issue within OpenSSL ASN1 parser while running on Travis
if os.getenv("TRAVIS"):
    FQDN = "buildbot"
else:
    try:
        FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]
    except socket.gaierror:
        click.echo("Failed to resolve fully qualified hostname of this machine, make sure hostname -f works")
        sys.exit(254)

if "." in FQDN:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
else:
    HOSTNAME, DOMAIN = FQDN, "local"
    click.echo("Unable to determine domain of this computer, falling back to local")

# TODO: lazier, otherwise gets evaluated before installing package
if os.path.exists("/etc/strongswan/ipsec.conf"): # fedora dafuq?!
    STRONGSWAN_PREFIX = "/etc/strongswan"
else:
    STRONGSWAN_PREFIX = "/etc"
