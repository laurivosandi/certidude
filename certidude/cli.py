#!/usr/bin/env python3
# coding: utf-8

import asyncore
import click
import configparser
import hashlib
import logging
import os
import pwd
import re
import signal
import socket
import subprocess
import sys
from certidude.helpers import expand_paths, \
    certidude_request_certificate
from certidude.signer import SignServer
from certidude.wrappers import CertificateAuthorityConfig, subject2dn
from datetime import datetime
from humanize import naturaltime
from ipaddress import ip_network, ip_address
from jinja2 import Environment, PackageLoader
from time import sleep
from setproctitle import setproctitle
from OpenSSL import crypto

env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

# Big fat warning:
# m2crypto overflows around 2030 because on 32-bit systems
# m2crypto does not support hardware engine support (?)
# m2crypto CRL object is pretty much useless

# pyopenssl has no straight-forward methods for getting RSA key modulus

# pyopenssl 0.13 bundled with Ubuntu 14.04 has no get_extension_count() for X509Req objects
assert hasattr(crypto.X509Req(), "get_extensions"), "You're running too old version of pyopenssl, upgrade to 0.15+"

# http://www.mad-hacking.net/documentation/linux/security/ssl-tls/creating-ca.xml
# https://kjur.github.io/jsrsasign/
# keyUsage, extendedKeyUsage - https://www.openssl.org/docs/apps/x509v3_config.html
# strongSwan key paths - https://wiki.strongswan.org/projects/1/wiki/SimpleCA

# Parse command-line argument defaults from environment
HOSTNAME = socket.gethostname()
FQDN = socket.getaddrinfo(HOSTNAME, 0, flags=socket.AI_CANONNAME)[0][3]
USERNAME = os.environ.get("USER")
NOW = datetime.utcnow().replace(tzinfo=None)
FIRST_NAME = None
SURNAME = None
EMAIL = None

if USERNAME:
    EMAIL = USERNAME + "@" + HOSTNAME

if os.getuid() >= 1000:
    _, _, _, _, gecos, _, _ = pwd.getpwnam(USERNAME)
    if " " in gecos:
        FIRST_NAME, SURNAME = gecos.split(" ", 1)
    else:
        FIRST_NAME = gecos


def load_config():
    path = os.getenv('CERTIDUDE_CONF')
    if path and os.path.isfile(path):
        return CertificateAuthorityConfig(path)
    return CertificateAuthorityConfig()


@click.command("spawn", help="Run privilege isolated signer processes")
@click.option("-k", "--kill", default=False, is_flag=True, help="Kill previous instances")
@click.option("-n", "--no-interaction", default=True, is_flag=True, help="Don't load password protected keys")
def certidude_spawn(kill, no_interaction):
    """
    Spawn processes for signers
    """
    # Check whether we have privileges
    os.umask(0o027)
    uid = os.getuid()
    if uid != 0:
        raise click.ClickException("Not running as root")

    # Process directories
    run_dir = "/run/certidude"
    signer_dir = os.path.join(run_dir, "signer")
    chroot_dir = os.path.join(signer_dir, "jail")

    # Prepare signer PID-s directory
    if not os.path.exists(signer_dir):
        click.echo("Creating: %s" % signer_dir)
        os.makedirs(signer_dir)

    # Preload charmap encoding for byte_string() function of pyOpenSSL
    # in order to enable chrooting
    "".encode("charmap")

    # Prepare chroot directories
    if not os.path.exists(os.path.join(chroot_dir, "dev")):
        os.makedirs(os.path.join(chroot_dir, "dev"))
    if not os.path.exists(os.path.join(chroot_dir, "dev", "urandom")):
        # TODO: use os.mknod instead
        os.system("mknod -m 444 %s c 1 9" % os.path.join(chroot_dir, "dev", "urandom"))

    ca_loaded = False
    config = load_config()
    for ca in config.all_authorities():
        socket_path = os.path.join(signer_dir, ca.slug + ".sock")
        pidfile_path = os.path.join(signer_dir, ca.slug + ".pid")

        try:
            with open(pidfile_path) as fh:
                pid = int(fh.readline())
                os.kill(pid, 0)
                click.echo("Found process with PID %d for %s" % (pid, ca.slug))
        except (ValueError, ProcessLookupError, FileNotFoundError):
            pid = 0

        if pid > 0:
            if kill:
                try:
                    click.echo("Killing %d" % pid)
                    os.kill(pid, signal.SIGTERM)
                    sleep(1)
                    os.kill(pid, signal.SIGKILL)
                    sleep(1)
                except ProcessLookupError:
                    pass
                ca_loaded = True
            else:
                ca_loaded = True
                continue

        child_pid = os.fork()

        if child_pid == 0:
            with open(pidfile_path, "w") as fh:
                fh.write("%d\n" % os.getpid())

            setproctitle("%s spawn %s" % (sys.argv[0], ca.slug))
            logging.basicConfig(
                filename="/var/log/certidude-%s.log" % ca.slug,
                level=logging.INFO)
            server = SignServer(socket_path, ca.private_key, ca.certificate.path,
                ca.certificate_lifetime, ca.basic_constraints, ca.key_usage,
                ca.extended_key_usage, ca.revocation_list_lifetime)
            asyncore.loop()
        else:
            click.echo("Spawned certidude signer process with PID %d at %s" % (child_pid, socket_path))
        ca_loaded = True

    if not ca_loaded:
        raise click.ClickException("No CA sections defined in configuration: {}".format(config.path))


@click.command("client", help="Setup X.509 certificates for application")
@click.argument("url") #, help="Certidude authority endpoint URL")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, '%s' by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--given-name", "-gn", default=FIRST_NAME, help="Given name of the person associted with the certificate, '%s' by default" % FIRST_NAME)
@click.option("--surname", "-sn", default=SURNAME, help="Surname of the person associted with the certificate, '%s' by default" % SURNAME)
@click.option("--key-usage", "-ku", help="Key usage attributes, none requested by default")
@click.option("--extended-key-usage", "-eku", help="Extended key usage attributes, none requested by default")
@click.option("--quiet", "-q", default=False, is_flag=True, help="Disable verbose output")
@click.option("--autosign", "-s", default=False, is_flag=True, help="Request for automatic signing if available")
@click.option("--wait", "-w", default=False, is_flag=True, help="Wait for certificate, by default return immideately")
@click.option("--key-path", "-k", default=HOSTNAME + ".key", help="Key path, %s.key by default" % HOSTNAME)
@click.option("--request-path", "-r", default=HOSTNAME + ".csr", help="Request path, %s.csr by default" % HOSTNAME)
@click.option("--certificate-path", "-c", default=HOSTNAME + ".crt", help="Certificate path, %s.crt by default" % HOSTNAME)
@click.option("--authority-path", "-a", default="ca.crt", help="Certificate authority certificate path, ca.crt by default")
def certidude_setup_client(quiet, **kwargs):
    return certidude_request_certificate(**kwargs)


@click.command("server", help="Set up OpenVPN server")
@click.argument("url")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--subnet", "-s", default="192.168.33.0/24", type=ip_network, help="OpenVPN subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", default="127.0.0.1", help="OpenVPN listening address, defaults to 127.0.0.1")
@click.option("--port", "-p", default=1194, type=click.IntRange(1,60000), help="OpenVPN listening port, 1194 by default")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@click.option("--config", "-o",
    default="/etc/openvpn/site-to-client.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-key", default=HOSTNAME + ".key", help="Key path, %s.key relative to --directory by default" % HOSTNAME)
@click.option("--request-path", "-csr", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to --directory by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to --directory by default" % HOSTNAME)
@click.option("--dhparam-path", "-dh", default="dhparam2048.pem", help="Diffie/Hellman parameters path, dhparam2048.pem relative to --directory by default")
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to --dir by default")
@expand_paths()
def certidude_setup_openvpn_server(url, config, subnet, route, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, dhparam_path, local, proto, port):
    # TODO: Intelligent way of getting last IP address in the subnet
    subnet_first = None
    subnet_last = None
    subnet_second = None
    for addr in subnet.hosts():
        if not subnet_first:
            subnet_first = addr
            continue
        if not subnet_second:
            subnet_second = addr
        subnet_last = addr

    if not os.path.exists(certificate_path):
        click.echo("As OpenVPN server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)

    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        key_usage="nonRepudiation,digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth,ikeIntermediate",
        wait=True)

    if not os.path.exists(dhparam_path):
        cmd = "openssl", "dhparam", "-out", dhparam_path, "2048"
        subprocess.check_call(cmd)

    if retval:
        return retval

    # TODO: Add dhparam
    config.write(env.get_template("openvpn-site-to-client.ovpn").render(locals()))

    click.echo("Generated %s" % config.name)
    click.echo()
    click.echo("Inspect newly created %s and start OpenVPN service:" % config.name)
    click.echo()
    click.secho("  service openvpn restart", bold=True)
    click.echo()


@click.command("client", help="Set up OpenVPN client")
@click.argument("url")
@click.argument("remote")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--config", "-o",
    default="/etc/openvpn/client-to-site.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-k", default=HOSTNAME + ".key", help="Key path, %s.key relative to --directory by default" % HOSTNAME)
@click.option("--request-path", "-r", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to --directory by default" % HOSTNAME)
@click.option("--certificate-path", "-c", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to --directory by default" % HOSTNAME)
@click.option("--authority-path", "-a", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to --dir by default")
@expand_paths()
def certidude_setup_openvpn_client(url, config, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, proto, remote):

    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        wait=True)

    if retval:
        return retval

    # TODO: Add dhparam
    config.write(env.get_template("openvpn-client-to-site.ovpn").render(locals()))

    click.echo("Generated %s" % config.name)
    click.echo()
    click.echo("Inspect newly created %s and start OpenVPN service:" % config.name)
    click.echo()
    click.echo("  service openvpn restart")
    click.echo()


@click.command("server", help="Set up strongSwan server")
@click.argument("url")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--fqdn", "-f", default=FQDN, help="Fully qualified hostname associated with the certificate")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, %s by default" % EMAIL)
@click.option("--subnet", "-s", default="192.168.33.0/24", type=ip_network, help="IPsec virtual subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", default=None, type=ip_address, help="IP address associated with the certificate, none by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@click.option("--config", "-o",
    default="/etc/ipsec.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="strongSwan configuration file, /etc/ipsec.conf by default")
@click.option("--secrets", "-s",
    default="/etc/ipsec.secrets",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="strongSwan secrets file, /etc/ipsec.secrets by default")
@click.option("--directory", "-d", default="/etc/ipsec.d", help="Directory for keys, /etc/ipsec.d by default")
@click.option("--key-path", "-key", default="private/%s.pem" % HOSTNAME, help="Key path, private/%s.pem by default" % HOSTNAME)
@click.option("--request-path", "-csr", default="reqs/%s.pem" % HOSTNAME, help="Request path, reqs/%s.pem by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default="certs/%s.pem" % HOSTNAME, help="Certificate path, certs/%s.pem by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="cacerts/ca.pem", help="Certificate authority certificate path, cacerts/ca.pem by default")
@expand_paths()
def certidude_setup_strongswan_server(url, config, secrets, subnet, route, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, local, fqdn):

    if not os.path.exists(certificate_path):
        click.echo("As strongSwan server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)

    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        key_usage="nonRepudiation,digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth,1.3.6.1.5.5.8.2.2",
        ip_address=local,
        dns=fqdn,
        wait=True)

    if retval:
        return retval

    config.write(env.get_template("strongswan-site-to-client.conf").render(locals()))
    secrets.write(": RSA %s\n" % key_path)

    click.echo("Generated %s and %s" % (config.name, secrets.name))
    click.echo()
    click.echo("Inspect newly created %s and start strongSwan service:" % config.name)
    click.echo()
    click.echo("  apt-get install strongswan strongswan-starter strongswan-ikev2")
    click.secho("  service strongswan restart", bold=True)
    click.echo()


@click.command("client", help="Set up strongSwan client")
@click.argument("url")
@click.argument("remote")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--config", "-o",
    default="/etc/ipsec.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="strongSwan configuration file, /etc/ipsec.conf by default")
@click.option("--secrets", "-s",
    default="/etc/ipsec.secrets",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="strongSwan secrets file, /etc/ipsec.secrets by default")
@click.option("--dpdaction", "-d",
    default="restart",
    type=click.Choice(["none", "clear", "hold", "restart"]),
    help="Action upon dead peer detection; either none, clear, hold or restart")
@click.option("--auto", "-a",
    default="start",
    type=click.Choice(["ignore", "add", "route", "start"]),
    help="Operation at startup; either ignore, add, route or start")
@click.option("--directory", "-d", default="/etc/ipsec.d", help="Directory for keys, /etc/ipsec.d by default")
@click.option("--key-path", "-key", default="private/%s.pem" % HOSTNAME, help="Key path, private/%s.pem by default" % HOSTNAME)
@click.option("--request-path", "-csr", default="reqs/%s.pem" % HOSTNAME, help="Request path, reqs/%s.pem by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default="certs/%s.pem" % HOSTNAME, help="Certificate path, certs/%s.pem by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="cacerts/ca.pem", help="Certificate authority certificate path, cacerts/ca.pem by default")
@expand_paths()
def certidude_setup_strongswan_client(url, config, secrets, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, remote, auto, dpdaction):

    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        wait=True)

    if retval:
        return retval

    # TODO: Add dhparam
    config.write(env.get_template("strongswan-client-to-site.conf").render(locals()))
    secrets.write(": RSA %s\n" % key_path)

    click.echo("Generated %s and %s" % (config.name, secrets.name))
    click.echo()
    click.echo("Inspect newly created %s and start strongSwan service:" % config.name)
    click.echo()
    click.echo("  apt-get install strongswan strongswan-starter")
    click.echo("  service strongswan restart")
    click.echo()


@click.command("networkmanager", help="Set up strongSwan client via NetworkManager")
@click.argument("url")
@click.argument("remote")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--directory", "-d", default="/etc/ipsec.d", help="Directory for keys, /etc/ipsec.d by default")
@click.option("--key-path", "-key", default="private/%s.pem" % HOSTNAME, help="Key path, private/%s.pem by default" % HOSTNAME)
@click.option("--request-path", "-csr", default="reqs/%s.pem" % HOSTNAME, help="Request path, reqs/%s.pem by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default="certs/%s.pem" % HOSTNAME, help="Certificate path, certs/%s.pem by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="cacerts/ca.pem", help="Certificate authority certificate path, cacerts/ca.pem by default")
@expand_paths()
def certidude_setup_strongswan_networkmanager(url, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, remote):

    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        wait=True)

    if retval:
        return retval

    csummer = hashlib.sha1()
    csummer.update(remote.encode("ascii"))
    csum = csummer.hexdigest()
    uuid = csum[:8] + "-" + csum[8:12] + "-" + csum[12:16] + "-" + csum[16:20] + "-" + csum[20:32]

    config = configparser.ConfigParser()
    config.add_section("connection")
    config.add_section("vpn")
    config.add_section("ipv4")

    config.set("connection", "id", remote)
    config.set("connection", "uuid", uuid)
    config.set("connection", "type", "vpn")
    config.set("connection", "autoconnect", "true")

    config.set("vpn", "service-type", "org.freedesktop.NetworkManager.strongswan")
    config.set("vpn", "userkey", key_path)
    config.set("vpn", "usercert", certificate_path)
    config.set("vpn", "encap", "no")
    config.set("vpn", "address", remote)
    config.set("vpn", "virtual", "yes")
    config.set("vpn", "method", "key")
    config.set("vpn", "certificate", authority_path)
    config.set("vpn", "ipcomp", "no")

    config.set("ipv4", "method", "auto")

    # Prevent creation of files with liberal permissions
    os.umask(0o277)

    # Write keyfile
    with open(os.path.join("/etc/NetworkManager/system-connections", remote), "w") as configfile:
        config.write(configfile)

    # TODO: Avoid race condition here
    sleep(3)

    # Tell NetworkManager to bring up the VPN connection
    subprocess.call(("nmcli", "c", "up", "uuid", uuid))


@click.command("production", help="Set up nginx and uwsgi")
@click.option("--username", default="certidude", help="Service user account, created if necessary, 'certidude' by default")
@click.option("--hostname", default=HOSTNAME, help="nginx hostname, '%s' by default" % HOSTNAME)
@click.option("--static-path", default=os.path.join(os.path.dirname(__file__), "static"), help="Static files")
@click.option("--kerberos-keytab", default="/etc/certidude.keytab", help="Specify Kerberos keytab")
@click.option("--nginx-config", "-n",
    default="/etc/nginx/nginx.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="nginx configuration, /etc/nginx/nginx.conf by default")
@click.option("--uwsgi-config", "-u",
    default="/etc/uwsgi/apps-available/certidude.ini",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="uwsgi configuration, /etc/uwsgi/ by default")
def certidude_setup_production(username, hostname, push_server, nginx_config, uwsgi_config, static_path, kerberos_keytab):
    try:
        pwd.getpwnam(username)
        click.echo("Username '%s' already exists, excellent!" % username)
    except KeyError:
        cmd = "adduser", "--system",  "--no-create-home", "--group", username
        subprocess.check_call(cmd)

    if subprocess.call("net ads testjoin", shell=True):
        click.echo("Domain membership check failed, 'net ads testjoin' returned non-zero value", stderr=True)
        exit(255)

    if not os.path.exists(kerberos_keytab):
        subprocess.call("KRB5_KTNAME=FILE:" + kerberos_keytab + " net ads keytab add HTTP -P")
        click.echo("Created Kerberos keytab in '%s'" % kerberos_keytab)

    if not static_path.endswith("/"):
        static_path += "/"

    nginx_config.write(env.get_template("nginx.conf").render(locals()))
    click.echo("Generated: %s" % nginx_config.name)
    uwsgi_config.write(env.get_template("uwsgi.ini").render(locals()))
    click.echo("Generated: %s" % uwsgi_config.name)

    if os.path.exists("/etc/uwsgi/apps-enabled/certidude.ini"):
        os.unlink("/etc/uwsgi/apps-enabled/certidude.ini")
    os.symlink(uwsgi_config.name, "/etc/uwsgi/apps-enabled/certidude.ini")
    click.echo("Symlinked %s -> /etc/uwsgi/apps-enabled/certidude.ini" % uwsgi_config.name)

    if not push_server:
        click.echo("Remember to install nginx with wandenberg/nginx-push-stream-module!")


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, hostname by default")
@click.option("--country", "-c", default="ee", help="Country, Estonia by default")
@click.option("--state", "-s", default="Harjumaa", help="State or country, Harjumaa by default")
@click.option("--locality", "-l", default="Tallinn", help="City or locality, Tallinn by default")
@click.option("--authority-lifetime", default=20*365, help="Authority certificate lifetime in days, 7300 days (20 years) by default")
@click.option("--certificate-lifetime", default=5*365, help="Certificate lifetime in days, 1825 days (5 years) by default")
@click.option("--revocation-list-lifetime", default=1, help="Revocation list lifetime in days, 1 day by default")
@click.option("--organization", "-o", default="Example LLC", help="Company or organization name")
@click.option("--organizational-unit", "-ou", default="Certification Department")
@click.option("--pkcs11", default=False, is_flag=True, help="Use PKCS#11 token instead of files")
@click.option("--crl-distribution-url", default=None, help="CRL distribution URL")
@click.option("--ocsp-responder-url", default=None, help="OCSP responder URL")
@click.option("--email-address", default=EMAIL, help="CA e-mail address")
@click.option("--inbox", default="imap://user:pass@host:port/INBOX", help="Inbound e-mail server")
@click.option("--outbox", default="smtp://localhost", help="Outbound e-mail server")
@click.option("--push-server", default="", help="Streaming nginx push server")
@click.argument("directory")
def certidude_setup_authority(parent, country, state, locality, organization, organizational_unit, common_name, directory, certificate_lifetime, authority_lifetime, revocation_list_lifetime, pkcs11, crl_distribution_url, ocsp_responder_url, email_address, inbox, outbox, push_server):

    publish_certificate_url = push_server + "/publish/%(request_sha1sum)s"
    subscribe_certificate_url = push_server + "/subscribe/%(request_sha1sum)s"

    slug = os.path.basename(directory[:-1] if directory.endswith('/') else directory)
    if not slug:
        raise click.ClickException("Please supply proper target path")
    # Make sure slug is valid
    if not re.match(r"^[_a-zA-Z0-9]+$", slug):
        raise click.ClickException("CA name can contain only alphanumeric and '_' characters")

    if os.path.lexists(directory):
        raise click.ClickException("Output directory {} already exists.".format(directory))

    click.echo("CA configuration files are saved to: {}".format(directory))

    click.echo("Generating 4096-bit RSA key...")

    if pkcs11:
        raise NotImplementedError("Hardware token support not yet implemented!")
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

    if not crl_distribution_url:
        crl_distribution_url = "http://%s/api/%s/revoked/" % (common_name, slug)

    # File paths
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")
    ca_crl = os.path.join(directory, "ca_crl.pem")
    crl_distribution_points = "URI:%s" % crl_distribution_url

    ca = crypto.X509()
    ca.set_version(2) # This corresponds to X.509v3
    ca.set_serial_number(1)
    ca.get_subject().CN = common_name
    ca.get_subject().C = country
    ca.get_subject().ST = state
    ca.get_subject().L = locality
    ca.get_subject().O = organization
    ca.get_subject().OU = organizational_unit
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(authority_lifetime * 24 * 60 * 60)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions([
        crypto.X509Extension(
            b"basicConstraints",
            True,
            b"CA:TRUE"),
        crypto.X509Extension(
            b"keyUsage",
            True,
            b"keyCertSign, cRLSign"),
        crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject = ca),
        crypto.X509Extension(
            b"crlDistributionPoints",
            False,
            crl_distribution_points.encode("ascii"))
    ])

    if email_address:
        subject_alt_name = "email:%s" % email_address
        ca.add_extensions([
            crypto.X509Extension(
                b"subjectAltName",
                False,
                subject_alt_name.encode("ascii"))
        ])

    if ocsp_responder_url:
        raise NotImplementedError()

    """
        ocsp_responder_url = "http://%s/api/%s/ocsp/" % (common_name, slug)
        authority_info_access = "OCSP;URI:%s" % ocsp_responder_url
        ca.add_extensions([
            crypto.X509Extension(
                b"authorityInfoAccess",
                False,
                authority_info_access.encode("ascii"))
        ])
    """

    click.echo("Signing %s..." % subject2dn(ca.get_subject()))

    # openssl x509 -in ca_crt.pem -outform DER | sha256sum
    # openssl x509 -fingerprint -in ca_crt.pem

    ca.sign(key, "sha256")

    os.umask(0o027)
    if not os.path.exists(directory):
        os.makedirs(directory)

    os.umask(0o007)

    for subdir in ("signed", "requests", "revoked"):
        if not os.path.exists(os.path.join(directory, subdir)):
            os.mkdir(os.path.join(directory, subdir))
    with open(ca_crl, "wb") as fh:
        crl = crypto.CRL()
        fh.write(crl.export(ca, key, days=revocation_list_lifetime))
    with open(os.path.join(directory, "serial"), "w") as fh:
        fh.write("1")

    os.umask(0o027)
    with open(ca_crt, "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

    os.umask(0o077)
    with open(ca_key, "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(os.path.join(directory, "openssl.cnf.example"), "w") as fh:
        fh.write(env.get_template("openssl.cnf").render(locals()))

    click.echo("You need to copy the contents of the 'openssl.cnf.example'")
    click.echo("to system-wide OpenSSL configuration file, usually located")
    click.echo("at /etc/ssl/openssl.cnf")

    click.echo()
    click.echo("Use following commands to inspect the newly created files:")
    click.echo()
    click.echo("  openssl crl -inform PEM -text -noout -in %s" % ca_crl)
    click.echo("  openssl x509 -text -noout -in %s" % ca_crt)
    click.echo("  openssl rsa -check -in %s" % ca_key)
    click.echo("  openssl verify -CAfile %s %s" % (ca_crt, ca_crt))
    click.echo()
    click.echo("Use following to launch privilege isolated signer processes:")
    click.echo()
    click.echo("  certidude spawn")
    click.echo()
    click.echo("Use following command to serve CA read-only:")
    click.echo()
    click.echo("  certidude serve")


@click.command("list", help="List certificates")
@click.argument("ca", nargs=-1)
@click.option("--verbose", "-v", default=False, is_flag=True, help="Verbose output")
@click.option("--show-key-type", "-k", default=False, is_flag=True, help="Show key type and length")
@click.option("--show-path", "-p", default=False, is_flag=True, help="Show filesystem paths")
@click.option("--show-extensions", "-e", default=False, is_flag=True, help="Show X.509 Certificate Extensions")
@click.option("--hide-requests", "-h", default=False, is_flag=True, help="Hide signing requests")
@click.option("--show-signed", "-s", default=False, is_flag=True, help="Show signed certificates")
@click.option("--show-revoked", "-r", default=False, is_flag=True, help="Show revoked certificates")
def certidude_list(ca, verbose, show_key_type, show_extensions, show_path, show_signed, show_revoked, hide_requests):
    # Statuses:
    #   s - submitted
    #   v - valid
    #   e - expired
    #   y - not valid yet
    #   r - revoked

    from pycountry import countries
    def dump_common(j):

        person = [j for j in (j.given_name, j.surname) if j]
        if person:
            click.echo("Associated person: %s" % " ".join(person) + (" <%s>" % j.email_address if j.email_address else ""))
        elif j.email_address:
            click.echo("Associated e-mail: " + j.email_address)

        bits = [j for j in (
            countries.get(alpha2=j.country_code.upper()).name if
            j.country_code else "",
            j.state_or_county,
            j.city,
            j.organization,
            j.organizational_unit) if j]
        if bits:
            click.echo("Organization: %s" % ", ".join(bits))

        if show_key_type:
            click.echo("Key type: %s-bit %s" % (j.key_length, j.key_type))

        if show_extensions:
            for key, value, data in j.extensions:
                click.echo(("Extension " + key + ":").ljust(50) + " " + value)
        else:
            if j.key_usage:
                click.echo("Key usage: " + j.key_usage)
            if j.fqdn:
                click.echo("Associated hostname: " + j.fqdn)

    config = load_config()

    wanted_list = None
    if ca:
        missing = list(set(ca) - set(config.ca_list))
        if missing:
            raise click.NoSuchOption(option_name='', message="Unable to find certificate authority.", possibilities=config.ca_list)
        wanted_list = ca

    for ca in config.all_authorities(wanted_list):
        if not hide_requests:
            for j in ca.get_requests():
                if not verbose:
                    click.echo("s " + j.path + " " + j.distinguished_name)
                    continue
                click.echo(click.style(j.common_name, fg="blue"))
                click.echo("=" * len(j.common_name))
                click.echo("State: ? " + click.style("submitted", fg="yellow") + " " + naturaltime(j.created) + click.style(", %s" %j.created,  fg="white"))

                dump_common(j)

                # Calculate checksums for cross-checking
                import hashlib
                md5sum = hashlib.md5()
                sha1sum = hashlib.sha1()
                sha256sum = hashlib.sha256()
                with open(j.path, "rb") as fh:
                    buf = fh.read()
                    md5sum.update(buf)
                    sha1sum.update(buf)
                    sha256sum.update(buf)
                click.echo("MD5 checksum: %s" % md5sum.hexdigest())
                click.echo("SHA-1 checksum: %s" % sha1sum.hexdigest())
                click.echo("SHA-256 checksum: %s" % sha256sum.hexdigest())

                if show_path:
                    click.echo("Details: openssl req -in %s -text -noout" % j.path)
                    click.echo("Sign: certidude sign %s" % j.path)
                click.echo()

        if show_signed:
            for j in ca.get_signed():
                if not verbose:
                    if j.signed < NOW and j.expires > NOW:
                        click.echo("v " + j.path + " " + j.distinguished_name)
                    elif NOW > j.expires:
                        click.echo("e " + j.path + " " + j.distinguished_name)
                    else:
                        click.echo("y " + j.path + " " + j.distinguished_name)
                    continue

                click.echo(click.style(j.common_name, fg="blue") + " " + click.style(j.serial_number_hex, fg="white"))
                click.echo("="*(len(j.common_name)+60))

                if j.signed < NOW and j.expires > NOW:
                    click.echo("Status: \u2713 " + click.style("valid", fg="green") + " " + naturaltime(j.expires) + click.style(", %s" %j.expires,  fg="white"))
                elif NOW > j.expires:
                    click.echo("Status: \u2717 " + click.style("expired", fg="red") + " " + naturaltime(j.expires) + click.style(", %s" %j.expires,  fg="white"))
                else:
                    click.echo("Status: \u2717 " + click.style("not valid yet", fg="red") + click.style(", %s" %j.expires,  fg="white"))
                dump_common(j)

                if show_path:
                    click.echo("Details: openssl x509 -in %s -text -noout" % j.path)
                    click.echo("Revoke: certidude revoke %s" % j.path)
                click.echo()

        if show_revoked:
            for j in ca.get_revoked():
                if not verbose:
                    click.echo("r " + j.path + " " + j.distinguished_name)
                    continue
                click.echo(click.style(j.common_name, fg="blue") + " " + click.style(j.serial_number_hex, fg="white"))
                click.echo("="*(len(j.common_name)+60))
                click.echo("Status: \u2717 " + click.style("revoked", fg="red") + " %s%s" % (naturaltime(NOW-j.changed), click.style(", %s" % j.changed, fg="white")))
                dump_common(j)
                if show_path:
                    click.echo("Details: openssl x509 -in %s -text -noout" % j.path)
                click.echo()

        click.echo()

@click.command("list", help="List Certificate Authorities")
@click.argument("ca")
#@config.pop_certificate_authority()
def cert_list(ca):

    mapping = {}

    config = load_config()

    click.echo("Listing certificates for: %s" % ca.certificate.subject.CN)

    for serial, reason, timestamp in ca.get_revoked():
        mapping[serial] = None, reason

    for certificate in ca.get_signed():
        mapping[certificate.serial] = certificate, None

    for serial, (certificate, reason) in sorted(mapping.items(), key=lambda j:j[0]):
        if not reason:
            click.echo("  %03d. %s %s" % (serial, certificate.subject.CN, (certificate.not_after-NOW)))
        else:
            click.echo("  %03d. Revoked due to: %s" % (serial, reason))

    for request in ca.get_requests():
        click.echo("  ⌛  %s" % request.subject.CN)

@click.command("sign", help="Sign certificates")
@click.argument("common_name")
@click.option("--overwrite", "-o", default=False, is_flag=True, help="Revoke valid certificate with same CN")
@click.option("--lifetime", "-l", help="Lifetime")
def certidude_sign(common_name, overwrite, lifetime):
    config = load_config()
    def iterate():
        for ca in config.all_authorities():
            for request in ca.get_requests():
                if request.common_name != common_name:
                    continue
                print(request.fingerprint(), request.common_name, request.path, request.key_usage)
                yield ca, request

    results = tuple(iterate())
    click.echo()

    click.echo("Press Ctrl-C to cancel singing these requests...")
    sys.stdin.readline()

    for ca, request in results:
        if request.signable:
            # Sign via signer process
            cert = ca.sign(request)
        else:
            # Sign directly using private key
            cert = ca.sign2(request, overwrite, True, lifetime)

        click.echo("Signed %s" % cert.distinguished_name)
        for key, value, data in cert.extensions:
            click.echo("Added extension %s: %s" % (key, value))
        click.echo()

@click.command("serve", help="Run built-in HTTP server")
@click.option("-u", "--user", default="certidude", help="Run as user")
@click.option("-p", "--port", default=80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
@click.option("-s", "--enable-signature", default=False, is_flag=True, help="Allow signing operations with private key of CA")
def certidude_serve(user, port, listen, enable_signature):

    logging.basicConfig(
        filename='/var/log/certidude.log',
        level=logging.DEBUG)

    click.echo("Serving API at %s:%d" % (listen, port))
    import pwd
    from wsgiref.simple_server import make_server, WSGIServer
    from socketserver import ThreadingMixIn
    from certidude.api import certidude_app, StaticResource

    class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
        pass

    click.echo("Listening on %s:%d" % (listen, port))

    app = certidude_app()

    app.add_sink(StaticResource(os.path.join(os.path.dirname(__file__), "static")))

    httpd = make_server(listen, port, app, ThreadingWSGIServer)

    if user:
        # Load required utils which cannot be imported from chroot
        # TODO: Figure out better approach
        from jinja2.debug import make_traceback as _make_traceback
        "".encode("charmap")

        _, _, uid, gid, gecos, root, shell = pwd.getpwnam(user)
        if uid == 0:
            click.echo("Please specify unprivileged user")
            exit(254)
        click.echo("Switching to user %s (uid=%d, gid=%d)" % (user, uid, gid))
        os.setgid(gid)
        os.setuid(uid)
        os.umask(0o007)
    elif os.getuid() == 0:
        click.echo("Warning: running as root, this is not recommended!")
    httpd.serve_forever()

@click.group("strongswan", help="strongSwan helpers")
def certidude_setup_strongswan(): pass

@click.group("openvpn", help="OpenVPN helpers")
def certidude_setup_openvpn(): pass

@click.group("setup", help="Getting started section")
def certidude_setup(): pass

@click.group()
def entry_point(): pass

certidude_setup_strongswan.add_command(certidude_setup_strongswan_server)
certidude_setup_strongswan.add_command(certidude_setup_strongswan_client)
certidude_setup_strongswan.add_command(certidude_setup_strongswan_networkmanager)
certidude_setup_openvpn.add_command(certidude_setup_openvpn_server)
certidude_setup_openvpn.add_command(certidude_setup_openvpn_client)
certidude_setup.add_command(certidude_setup_authority)
certidude_setup.add_command(certidude_setup_openvpn)
certidude_setup.add_command(certidude_setup_strongswan)
certidude_setup.add_command(certidude_setup_client)
certidude_setup.add_command(certidude_setup_production)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_spawn)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_list)
