
import click
import socket

FQDN = socket.getaddrinfo(socket.gethostname(), 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]

if "." in FQDN:
    HOSTNAME, DOMAIN = FQDN.split(".", 1)
else:
    HOSTNAME, DOMAIN = FQDN, "local"
    click.echo("Unable to determine domain of this computer, falling back to local")

EXTENSION_WHITELIST = set(["subjectAltName"])
