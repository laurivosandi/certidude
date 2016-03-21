#!/usr/bin/env python3
# coding: utf-8

import asyncore
import click
import hashlib
import logging
import os
import pwd
import re
import requests
import signal
import socket
import subprocess
import sys
from configparser import ConfigParser
from certidude import constants
from certidude.common import expand_paths, ip_address, ip_network
from datetime import datetime
from humanize import naturaltime
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
FQDN = socket.getaddrinfo(HOSTNAME, 0, socket.AF_INET, 0, 0, socket.AI_CANONNAME)[0][3]
USERNAME = os.environ.get("USER")
NOW = datetime.utcnow().replace(tzinfo=None)
FIRST_NAME = None
SURNAME = None
EMAIL = None

if USERNAME:
    EMAIL = USERNAME + "@" + FQDN

if os.getuid() >= 1000:
    _, _, _, _, gecos, _, _ = pwd.getpwnam(USERNAME)
    if " " in gecos:
        FIRST_NAME, SURNAME = gecos.split(" ", 1)
    else:
        FIRST_NAME = gecos


@click.command("spawn", help="Run processes for requesting certificates and configuring services")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
def certidude_request_spawn(fork):
    from certidude.helpers import certidude_request_certificate

    clients = ConfigParser()
    clients.readfp(open("/etc/certidude/client.conf"))

    services = ConfigParser()
    services.readfp(open("/etc/certidude/services.conf"))

    # Process directories
    run_dir = "/run/certidude"

    # Prepare signer PID-s directory
    if not os.path.exists(run_dir):
        click.echo("Creating: %s" % run_dir)
        os.makedirs(run_dir)

    for server in clients.sections():
        if clients.get(server, "managed") != "true":
            continue

        pid_path = os.path.join(run_dir, server + ".pid")

        try:
            with open(pid_path) as fh:
                pid = int(fh.readline())
                os.kill(pid, signal.SIGTERM)
                click.echo("Terminated process %d" % pid)
            os.unlink(pid_path)
        except EnvironmentError:
            pass

        if fork:
            child_pid = os.fork()
        else:
            child_pid = None

        if child_pid:
            click.echo("Spawned certificate request process with PID %d" % (child_pid))
            continue

        with open(pid_path, "w") as fh:
            fh.write("%d\n" % os.getpid())
        setproctitle("certidude request spawn %s" % server)
        retries = 30
        while retries > 0:
            try:
                certidude_request_certificate(
                    server,
                    clients.get(server, "key_path"),
                    clients.get(server, "request_path"),
                    clients.get(server, "certificate_path"),
                    clients.get(server, "authority_path"),
                    socket.gethostname(),
                    None,
                    autosign=True,
                    wait=True)
                break
            except requests.exceptions.Timeout:
                retries -= 1
                continue

        for endpoint in services.sections():
            if services.get(endpoint, "authority") != server:
                continue

            csummer = hashlib.sha1()
            csummer.update(endpoint.encode("ascii"))
            csum = csummer.hexdigest()
            uuid = csum[:8] + "-" + csum[8:12] + "-" + csum[12:16] + "-" + csum[16:20] + "-" + csum[20:32]

            # Set up IPsec via NetworkManager
            if services.get(endpoint, "service") == "network-manager/strongswan":

                config = ConfigParser()
                config.add_section("connection")
                config.add_section("vpn")
                config.add_section("ipv4")

                config.set("connection", "id", endpoint)
                config.set("connection", "uuid", uuid)
                config.set("connection", "type", "vpn")

                config.set("vpn", "service-type", "org.freedesktop.NetworkManager.strongswan")
                config.set("vpn", "userkey", clients.get(server, "key_path"))
                config.set("vpn", "usercert", clients.get(server, "certificate_path"))
                config.set("vpn", "encap", "no")
                config.set("vpn", "address", services.get(endpoint, "remote"))
                config.set("vpn", "virtual", "yes")
                config.set("vpn", "method", "key")
                config.set("vpn", "certificate", clients.get(server, "authority_path"))
                config.set("vpn", "ipcomp", "no")

                config.set("ipv4", "method", "auto")

                # Add routes, may need some more tweaking
                if services.has_option(endpoint, "route"):
                    for index, subnet in enumerate(services.get(endpoint, "route").split(","), start=1):
                        config.set("ipv4", "route%d" % index, subnet)

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write keyfile
                with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as configfile:
                    config.write(configfile)
                continue

            # Set up IPsec via /etc/ipsec.conf
            if services.get(endpoint, "service") == "strongswan":
                from ipsecparse import loads
                config = loads(open('/etc/ipsec.conf').read())
                config["conn", endpoint] = dict(
                    leftsourceip="%config",
                    left="%defaultroute",
                    leftcert=clients.get(server, "certificate_path"),
                    rightid="%any",
                    right=services.get(endpoint, "remote"),
                    rightsubnet=services.get(endpoint, "route"),
                    keyexchange="ikev2",
                    keyingtries="300",
                    dpdaction="restart",
                    closeaction="restart",
                    auto="start")
                with open("/etc/ipsec.conf.part", "w") as fh:
                    fh.write(config.dumps())
                os.rename("/etc/ipsec.conf.part", "/etc/ipsec.conf")

                # Regenerate /etc/ipsec.secrets
                with open("/etc/ipsec.secrets.part", "w") as fh:
                    for filename in os.listdir("/etc/ipsec.d/private"):
                        if not filename.endswith(".pem"):
                            continue
                        fh.write(": RSA /etc/ipsec.d/private/%s\n" % filename)
                os.rename("/etc/ipsec.secrets.part", "/etc/ipsec.secrets")

                # Attempt to reload config or start if it's not running
                if os.system("ipsec update") == 130:
                    os.system("ipsec start")
                continue



            # TODO: OpenVPN, Puppet, OpenLDAP, intranet HTTPS, <insert awesomeness here>

        os.unlink(pid_path)


@click.command("spawn", help="Run privilege isolated signer process")
@click.option("-k", "--kill", default=False, is_flag=True, help="Kill previous instance")
@click.option("-n", "--no-interaction", default=True, is_flag=True, help="Don't load password protected keys")
def certidude_signer_spawn(kill, no_interaction):
    """
    Spawn privilege isolated signer process
    """
    from certidude.signer import SignServer
    from certidude import config

    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    os.setgid(gid)

    # Check whether we have privileges
    os.umask(0o027)
    uid = os.getuid()
    if uid != 0:
        raise click.ClickException("Not running as root")

    # Process directories
    run_dir = "/run/certidude"

    # Prepare signer PID-s directory
    if not os.path.exists(run_dir):
        click.echo("Creating: %s" % run_dir)
        os.makedirs(run_dir)

    # Preload charmap encoding for byte_string() function of pyOpenSSL
    # in order to enable chrooting
    "".encode("charmap")

    # Prepare chroot directories
    chroot_dir = os.path.join(run_dir, "jail")
    if not os.path.exists(os.path.join(chroot_dir, "dev")):
        os.makedirs(os.path.join(chroot_dir, "dev"))
    if not os.path.exists(os.path.join(chroot_dir, "dev", "urandom")):
        # TODO: use os.mknod instead
        os.system("mknod -m 444 %s c 1 9" % os.path.join(chroot_dir, "dev", "urandom"))

    try:
        with open(config.SIGNER_PID_PATH) as fh:
            pid = int(fh.readline())
            os.kill(pid, 0)
            click.echo("Found process with PID %d" % pid)
    except EnvironmentError:
        pid = 0

    if pid > 0:
        if kill:
            try:
                click.echo("Killing %d" % pid)
                os.kill(pid, signal.SIGTERM)
                sleep(1)
                os.kill(pid, signal.SIGKILL)
                sleep(1)
            except EnvironmentError:
                pass

    child_pid = os.fork()

    if child_pid:
        click.echo("Spawned certidude signer process with PID %d at %s" % (child_pid, config.SIGNER_SOCKET_PATH))
        return

    setproctitle("certidude signer spawn")
    with open(config.SIGNER_PID_PATH, "w") as fh:
        fh.write("%d\n" % os.getpid())
    logging.basicConfig(
        filename="/var/log/signer.log",
        level=logging.INFO)
    server = SignServer()
    asyncore.loop()



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
    from certidude.helpers import certidude_request_certificate
    return certidude_request_certificate(**kwargs)


@click.command("server", help="Set up OpenVPN server")
@click.argument("url")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, %s by default" % FQDN)
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
    from certidude.helpers import certidude_request_certificate
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
        key_usage="digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth",
        wait=True)

    if not os.path.exists(dhparam_path):
        cmd = "openssl", "dhparam", "-out", dhparam_path, "2048"
        subprocess.check_call(cmd)

    if retval:
        return retval

    # TODO: Add dhparam
    config.write(env.get_template("openvpn-site-to-client.ovpn").render(vars()))

    click.echo("Generated %s" % config.name)
    click.echo()
    click.echo("Inspect newly created %s and start OpenVPN service:" % config.name)
    click.echo()
    click.secho("  service openvpn restart", bold=True)
    click.echo()


@click.command("nginx", help="Set up nginx as HTTPS server")
@click.argument("url")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, %s by default" % FQDN)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--tls-config",
    default="/etc/nginx/conf.d/tls.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="TLS configuration file of nginx, /etc/nginx/conf.d/tls.conf by default")
@click.option("--site-config", "-o",
    default="/etc/nginx/sites-available/%s.conf" % HOSTNAME,
    type=click.File(mode="w", atomic=True, lazy=True),
    help="Site configuration file of nginx, /etc/nginx/sites-available/%s.conf by default" % HOSTNAME)
@click.option("--directory", "-d", default="/etc/nginx/ssl", help="Directory for keys, /etc/nginx/ssl by default")
@click.option("--key-path", "-key", default=HOSTNAME + ".key", help="Key path, %s.key relative to -d by default" % HOSTNAME)
@click.option("--request-path", "-csr", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to -d by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to --directory by default" % HOSTNAME)
@click.option("--dhparam-path", "-dh", default="dhparam2048.pem", help="Diffie/Hellman parameters path, dhparam2048.pem relative to -d by default")
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to -d by default")
@click.option("--verify-client", "-vc", type=click.Choice(['optional', 'on', 'off']))
@expand_paths()
def certidude_setup_nginx(url, site_config, tls_config, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, dhparam_path, verify_client):
    # TODO: Intelligent way of getting last IP address in the subnet
    from certidude.helpers import certidude_request_certificate

    if not os.path.exists(certificate_path):
        click.echo("As HTTPS server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)
        click.echo()
    retval = certidude_request_certificate(url, key_path, request_path,
        certificate_path, authority_path, common_name, org_unit,
        key_usage="digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth",
        dns = constants.FQDN, wait=True, bundle=True)

    if not os.path.exists(dhparam_path):
        cmd = "openssl", "dhparam", "-out", dhparam_path, "2048"
        subprocess.check_call(cmd)

    if retval:
        return retval

    context = globals() # Grab constants.BLAH
    context.update(locals())

    if os.path.exists(site_config.name):
        click.echo("Configuration file %s already exists, not overwriting" % site_config.name)
    else:
        site_config.write(env.get_template("nginx-https-site.conf").render(context))
        click.echo("Generated %s" % site_config.name)

    if os.path.exists(tls_config.name):
        click.echo("Configuration file %s already exists, not overwriting" % tls_config.name)
    else:
        tls_config.write(env.get_template("nginx-tls.conf").render(context))
        click.echo("Generated %s" % tls_config.name)

    click.echo()
    click.echo("Inspect configuration files, enable it and start nginx service:")
    click.echo()
    click.echo("  ln -s %s /etc/nginx/sites-enabled/%s" % (
        os.path.relpath(site_config.name, "/etc/nginx/sites-enabled"),
        os.path.basename(site_config.name)))
    click.secho("  service nginx restart", bold=True)
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
    from certidude.helpers import certidude_request_certificate
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
    config.write(env.get_template("openvpn-client-to-site.ovpn").render(vars()))

    click.echo("Generated %s" % config.name)
    click.echo()
    click.echo("Inspect newly created %s and start OpenVPN service:" % config.name)
    click.echo()
    click.echo("  service openvpn restart")
    click.echo()


@click.command("server", help="Set up strongSwan server")
@click.argument("url")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, %s by default" % FQDN)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--fqdn", "-f", default=FQDN, help="Fully qualified hostname associated with the certificate")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, %s by default" % EMAIL)
@click.option("--subnet", "-sn", default=u"192.168.33.0/24", type=ip_network, help="IPsec virtual subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", type=ip_address, help="IP address associated with the certificate, none by default")
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
    if "." not in common_name:
        raise ValueError("Hostname has to be fully qualified!")
    if not local:
        raise ValueError("Please specify local IP address")

    if not os.path.exists(certificate_path):
        click.echo("As strongSwan server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)
    from certidude.helpers import certidude_request_certificate
    retval = certidude_request_certificate(
        url,
        key_path,
        request_path,
        certificate_path,
        authority_path,
        common_name,
        org_unit,
        email_address,
        key_usage="digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth,1.3.6.1.5.5.8.2.2",
        ip_address=local,
        dns=fqdn,
        wait=True)

    if retval:
        return retval

    config.write(env.get_template("strongswan-site-to-client.conf").render(vars()))
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
    from certidude.helpers import certidude_request_certificate
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
    config.write(env.get_template("strongswan-client-to-site.conf").render(vars()))
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
    from certidude.helpers import certidude_request_certificate
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

    config = ConfigParser()
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


@click.command("production", help="Set up nginx, uwsgi and cron")
@click.option("--username", default="certidude", help="Service user account, created if necessary, 'certidude' by default")
@click.option("--hostname", default=HOSTNAME, help="nginx hostname, '%s' by default" % HOSTNAME)
@click.option("--static-path", default=os.path.join(os.path.dirname(__file__), "static"), help="Static files")
@click.option("--kerberos-keytab", default="/etc/certidude/server.keytab", help="Specify Kerberos keytab")
@click.option("--push-server", default=None, help="Push server URL")
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
        click.echo("Domain membership check failed, 'net ads testjoin' returned non-zero value", err=True)
        exit(255)

    if not os.path.exists(kerberos_keytab):
        subprocess.call("KRB5_KTNAME=FILE:" + kerberos_keytab + " net ads keytab add HTTP -P")
        click.echo("Created service principal in Kerberos keytab '%s'" % kerberos_keytab)

    if os.path.exists("/etc/krb5.keytab") and os.path.exists("/etc/samba/smb.conf"):
        # Fetch Kerberos ticket for system account
        cp = ConfigParser()
        cp.read("/etc/samba/smb.conf")
        domain = cp.get("global", "realm").lower()
        base = ",".join(["dc=" + j for j in domain.split(".")])
        with open("/etc/cron.hourly/certidude", "w") as fh:
            fh.write("#!/bin/bash\n")
            fh.write("KRB5CCNAME=/run/certidude/krb5cc-new kinit -k %s$\n" % cp.get("global", "netbios name"))
            fh.write("chown certidude /run/certidude/krb5cc-new\n")
            fh.write("mv /run/certidude/krb5cc-new /run/certidude/krb5cc\n")
        os.chmod("/etc/cron.hourly/certidude", 0o755)
        click.echo("Created /etc/cron.hourly/certidude for automatic Kerberos TGT renewal")
    else:
        click.echo("Warning: cronjob for Kerberos ticket renewal not created, LDAP with GSSAPI will not be available!")


    if not static_path.endswith("/"):
        static_path += "/"

    nginx_config.write(env.get_template("nginx.conf").render(vars()))
    click.echo("Generated: %s" % nginx_config.name)
    uwsgi_config.write(env.get_template("uwsgi.ini").render(vars()))
    click.echo("Generated: %s" % uwsgi_config.name)

    if os.path.exists("/etc/uwsgi/apps-enabled/certidude.ini"):
        os.unlink("/etc/uwsgi/apps-enabled/certidude.ini")
    os.symlink(uwsgi_config.name, "/etc/uwsgi/apps-enabled/certidude.ini")
    click.echo("Symlinked %s -> /etc/uwsgi/apps-enabled/certidude.ini" % uwsgi_config.name)

    if not push_server:
        click.echo("Remember to install nchan instead of regular nginx!")


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, fully qualified hostname by default")
@click.option("--country", "-c", default=None, help="Country, none by default")
@click.option("--state", "-s", default=None, help="State or country, none by default")
@click.option("--locality", "-l", default=None, help="City or locality, none by default")
@click.option("--authority-lifetime", default=20*365, help="Authority certificate lifetime in days, 7300 days (20 years) by default")
@click.option("--certificate-lifetime", default=5*365, help="Certificate lifetime in days, 1825 days (5 years) by default")
@click.option("--revocation-list-lifetime", default=1, help="Revocation list lifetime in days, 1 day by default")
@click.option("--organization", "-o", default=None, help="Company or organization name")
@click.option("--organizational-unit", "-ou", default=None)
@click.option("--pkcs11", default=False, is_flag=True, help="Use PKCS#11 token instead of files")
@click.option("--crl-distribution-url", default=None, help="CRL distribution URL")
@click.option("--ocsp-responder-url", default=None, help="OCSP responder URL")
@click.option("--push-server", default="", help="Streaming nginx push server")
@click.option("--email-address", default="certidude@" + FQDN, help="E-mail address of the CA")
@click.option("--directory", default=os.path.join("/var/lib/certidude", FQDN), help="Directory for authority files, /var/lib/certidude/ by default")
def certidude_setup_authority(parent, country, state, locality, organization, organizational_unit, common_name, directory, certificate_lifetime, authority_lifetime, revocation_list_lifetime, pkcs11, crl_distribution_url, ocsp_responder_url, push_server, email_address):

    # Make sure common_name is valid
    if not re.match(r"^[\.\-_a-zA-Z0-9]+$", common_name):
        raise click.ClickException("CA name can contain only alphanumeric, '_' and '-' characters")

    if os.path.lexists(directory):
        raise click.ClickException("Output directory {} already exists.".format(directory))

    certidude_conf = os.path.join("/etc/certidude/server.conf")
    if os.path.exists(certidude_conf):
        raise click.ClickException("Configuration file %s already exists" % certidude_conf)

    click.echo("CA configuration files are saved to: {}".format(directory))

    click.echo("Generating 4096-bit RSA key...")

    if pkcs11:
        raise NotImplementedError("Hardware token support not yet implemented!")
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

    if not crl_distribution_url:
        crl_distribution_url = "http://%s/api/revoked/" % common_name

    # File paths
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")
    ca_crl = os.path.join(directory, "ca_crl.pem")
    crl_distribution_points = "URI:%s" % crl_distribution_url

    ca = crypto.X509()
    ca.set_version(2) # This corresponds to X.509v3
    ca.set_serial_number(1)
    ca.get_subject().CN = common_name

    if country:
        ca.get_subject().C = country
    if state:
        ca.get_subject().ST = state
    if locality:
        ca.get_subject().L = locality
    if organization:
        ca.get_subject().O = organization
    if organizational_unit:
        ca.get_subject().OU = organizational_unit

    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(authority_lifetime * 24 * 60 * 60)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)

    # add_extensions shall be called only once and
    # there has to be only one subjectAltName!
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
            b"extendedKeyUsage",
            False,
            b"serverAuth,1.3.6.1.5.5.8.2.2"),
        crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject = ca),
        crypto.X509Extension(
            b"crlDistributionPoints",
            False,
            crl_distribution_points.encode("ascii")),
        crypto.X509Extension(
            b"subjectAltName",
            False,
            "DNS: %s, email: %s" % (common_name.encode("ascii"), email_address.encode("ascii")))
    ])

    if ocsp_responder_url:
        raise NotImplementedError()

    """
        ocsp_responder_url = "http://%s/api/ocsp/" % common_name
        authority_info_access = "OCSP;URI:%s" % ocsp_responder_url
        ca.add_extensions([
            crypto.X509Extension(
                b"authorityInfoAccess",
                False,
                authority_info_access.encode("ascii"))
        ])
    """

    click.echo("Signing %s..." % ca.get_subject())

    # openssl x509 -in ca_crt.pem -outform DER | sha256sum
    # openssl x509 -fingerprint -in ca_crt.pem

    ca.sign(key, "sha256")

    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    os.setgid(gid)

    # Create authority directory with 750 permissions
    os.umask(0o027)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Create subdirectories with 770 permissions
    os.umask(0o007)
    for subdir in ("signed", "requests", "revoked"):
        if not os.path.exists(os.path.join(directory, subdir)):
            os.mkdir(os.path.join(directory, subdir))

    # Create CRL and serial file with 644 permissions
    os.umask(0o133)
    with open(ca_crl, "wb") as fh:
        crl = crypto.CRL()
        fh.write(crl.export(ca, key, days=revocation_list_lifetime))
    with open(os.path.join(directory, "serial"), "w") as fh:
        fh.write("1")

    # Set permission bits to 640
    os.umask(0o137)
    with open(certidude_conf, "w") as fh:
        fh.write(env.get_template("certidude.conf").render(vars()))
    with open(ca_crt, "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

    # Set permission bits to 600
    os.umask(0o177)
    with open(ca_key, "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    click.echo()
    click.echo("Use following commands to inspect the newly created files:")
    click.echo()
    click.echo("  openssl crl -inform PEM -text -noout -in %s | less" % ca_crl)
    click.echo("  openssl x509 -text -noout -in %s | less" % ca_crt)
    click.echo("  openssl rsa -check -in %s" % ca_key)
    click.echo("  openssl verify -CAfile %s %s" % (ca_crt, ca_crt))
    click.echo()
    click.echo("Use following to launch privilege isolated signer processes:")
    click.echo()
    click.echo("  certidude signer spawn -k")
    click.echo()
    click.echo("Use following command to serve CA read-only:")
    click.echo()
    click.echo("  certidude serve")


@click.command("list", help="List certificates")
@click.option("--verbose", "-v", default=False, is_flag=True, help="Verbose output")
@click.option("--show-key-type", "-k", default=False, is_flag=True, help="Show key type and length")
@click.option("--show-path", "-p", default=False, is_flag=True, help="Show filesystem paths")
@click.option("--show-extensions", "-e", default=False, is_flag=True, help="Show X.509 Certificate Extensions")
@click.option("--hide-requests", "-h", default=False, is_flag=True, help="Hide signing requests")
@click.option("--show-signed", "-s", default=False, is_flag=True, help="Show signed certificates")
@click.option("--show-revoked", "-r", default=False, is_flag=True, help="Show revoked certificates")
def certidude_list(verbose, show_key_type, show_extensions, show_path, show_signed, show_revoked, hide_requests):
    # Statuses:
    #   s - submitted
    #   v - valid
    #   e - expired
    #   y - not valid yet
    #   r - revoked

    from certidude import authority

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


    if not hide_requests:
        for j in authority.list_requests():

            if not verbose:
                click.echo("s " + j.path + " " + j.identity)
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
        for j in authority.list_signed():
            if not verbose:
                if j.signed < NOW and j.expires > NOW:
                    click.echo("v " + j.path + " " + j.identity)
                elif NOW > j.expires:
                    click.echo("e " + j.path + " " + j.identity)
                else:
                    click.echo("y " + j.path + " " + j.identity)
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
        for j in authority.list_revoked():
            if not verbose:
                click.echo("r " + j.path + " " + j.identity)
                continue
            click.echo(click.style(j.common_name, fg="blue") + " " + click.style(j.serial_number_hex, fg="white"))
            click.echo("="*(len(j.common_name)+60))
            click.echo("Status: \u2717 " + click.style("revoked", fg="red") + " %s%s" % (naturaltime(NOW-j.changed), click.style(", %s" % j.changed, fg="white")))
            dump_common(j)
            if show_path:
                click.echo("Details: openssl x509 -in %s -text -noout" % j.path)
            click.echo()

    click.echo()


@click.command("sign", help="Sign certificates")
@click.argument("common_name")
@click.option("--overwrite", "-o", default=False, is_flag=True, help="Revoke valid certificate with same CN")
@click.option("--lifetime", "-l", help="Lifetime")
def certidude_sign(common_name, overwrite, lifetime):
    from certidude import authority
    request = authority.get_request(common_name)
    if request.signable:
        # Sign via signer process
        cert = authority.sign(request)
    else:
        # Sign directly using private key
        cert = authority.sign2(request, overwrite, True, lifetime)

    click.echo("Signed %s" % cert.identity)
    for key, value, data in cert.extensions:
        click.echo("Added extension %s: %s" % (key, value))
    click.echo()


@click.command("serve", help="Run built-in HTTP server")
@click.option("-u", "--user", default="certidude", help="Run as user")
@click.option("-p", "--port", default=80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
@click.option("-s", "--enable-signature", default=False, is_flag=True, help="Allow signing operations with private key of CA")
def certidude_serve(user, port, listen, enable_signature):
    from certidude import config

    click.echo("Users subnets: %s" %
        ", ".join([str(j) for j in config.USER_SUBNETS]))
    click.echo("Administrative subnets: %s" %
        ", ".join([str(j) for j in config.ADMIN_SUBNETS]))
    click.echo("Auto-sign enabled for following subnets: %s" %
        ", ".join([str(j) for j in config.AUTOSIGN_SUBNETS]))
    click.echo("Request submissions allowed from following subnets: %s" %
        ", ".join([str(j) for j in config.REQUEST_SUBNETS]))

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


    # TODO: Bind before dropping privileges,
    #       but create app (sqlite log files!) after dropping privileges
    app = certidude_app()

    app.add_sink(StaticResource(os.path.join(os.path.dirname(__file__), "static")))

    httpd = make_server(listen, port, app, ThreadingWSGIServer)

    if user:
        # Load required utils which cannot be imported from chroot
        # TODO: Figure out better approach
        from jinja2.debug import make_traceback as _make_traceback
        "".encode("charmap")

        restricted_groups = []

        if config.AUTHENTICATION_BACKENDS == {"pam"}:
            # PAM needs access to /etc/shadow
            import grp
            name, passwd, gid, mem = grp.getgrnam("shadow")
            click.echo("Adding current user to shadow group due to PAM authentication backend")
            restricted_groups.append(gid)

        _, _, uid, gid, gecos, root, shell = pwd.getpwnam(user)
        restricted_groups.append(gid)


        os.setgroups(restricted_groups)
        os.setgid(gid)
        os.setuid(uid)

        click.echo("Switched to user %s (uid=%d, gid=%d); member of groups %s" %
            (user, os.getuid(), os.getgid(), ", ".join([str(j) for j in os.getgroups()])))

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

@click.group("signer", help="Signer process management")
def certidude_signer(): pass

@click.group("request", help="CSR process management")
def certidude_request(): pass

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
certidude_setup.add_command(certidude_setup_nginx)
certidude_request.add_command(certidude_request_spawn)
certidude_signer.add_command(certidude_signer_spawn)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_signer)
entry_point.add_command(certidude_request)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_list)
