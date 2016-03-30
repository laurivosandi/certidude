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
from certidude.helpers import certidude_request_certificate
from certidude.common import expand_paths, ip_address, ip_network
from datetime import datetime, timedelta
from humanize import naturaltime
from jinja2 import Environment, PackageLoader
from time import sleep
from setproctitle import setproctitle


env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

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
        if clients.get(server, "trigger") != "interface up":
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
                    clients.get(server, "revocations_path"),
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

            # Intranet HTTPS handled by PKCS#12 bundle generation,
            # so it will not be implemented here

            if services.get(endpoint, "service") == "network-manager/openvpn":
                config = ConfigParser()
                config.add_section("connection")
                config.add_section("vpn")
                config.add_section("ipv4")
                config.add_section("ipv6")

                config.set("connection", "id", endpoint)
                config.set("connection", "uuid", uuid)
                config.set("connection", "type", "vpn")

                config.set("vpn", "service-type", "org.freedesktop.NetworkManager.openvpn")
                config.set("vpn", "connection-type", "tls")
                config.set("vpn", "comp-lzo", "yes")
                config.set("vpn", "cert-pass-flags", "0")
                config.set("vpn", "tap-dev", "yes")
                config.set("vpn", "remote-cert-tls", "server") # Assert TLS Server flag of X.509 certificate
                config.set("vpn", "remote", services.get(endpoint, "remote"))
                config.set("vpn", "key", clients.get(server, "key_path"))
                config.set("vpn", "cert", clients.get(server, "certificate_path"))
                config.set("vpn", "ca", clients.get(server, "authority_path"))

                config.set("ipv6", "method", "auto")

                config.set("ipv4", "method", "auto")
                config.set("ipv4", "never-default", "true")

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write keyfile
                with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as configfile:
                    config.write(configfile)
                continue


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
                config.set("vpn", "encap", "no")
                config.set("vpn", "virtual", "yes")
                config.set("vpn", "method", "key")
                config.set("vpn", "ipcomp", "no")
                config.set("vpn", "address", services.get(endpoint, "remote"))
                config.set("vpn", "userkey", clients.get(server, "key_path"))
                config.set("vpn", "usercert", clients.get(server, "certificate_path"))
                config.set("vpn", "certificate", clients.get(server, "authority_path"))

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

            # TODO: Puppet, OpenLDAP, <insert awesomeness here>

        os.unlink(pid_path)


@click.command("spawn", help="Restart privilege isolated signer process")
@click.option("-n", "--no-interaction", default=True, is_flag=True, help="Don't load password protected keys")
def certidude_signer_spawn(no_interaction):
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
@click.argument("server")
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
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl by default")
def certidude_setup_client(quiet, **kwargs):
    return certidude_request_certificate(**kwargs)


@click.command("server", help="Set up OpenVPN server")
@click.argument("server")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, %s by default" % FQDN)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--subnet", "-s", default="192.168.33.0/24", type=ip_network, help="OpenVPN subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", default="0.0.0.0", help="OpenVPN listening address, defaults to all interfaces")
@click.option("--port", "-p", default=1194, type=click.IntRange(1,60000), help="OpenVPN listening port, 1194 by default")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@click.option("--config", "-o",
    default="/etc/openvpn/site-to-client.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-key", default=HOSTNAME + ".key", help="Key path, %s.key relative to -d by default" % HOSTNAME)
@click.option("--request-path", "-csr", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to -d by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to -d by default" % HOSTNAME)
@click.option("--dhparam-path", "-dh", default="dhparam2048.pem", help="Diffie/Hellman parameters path, dhparam2048.pem relative to -d by default")
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to --dir by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl relative to -d by default")
@expand_paths()
def certidude_setup_openvpn_server(server, config, subnet, route, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, dhparam_path, local, proto, port):
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
    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path, revocations_path,
        common_name, org_unit, email_address,
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
@click.argument("server")
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
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to -d by default" % HOSTNAME)
@click.option("--dhparam-path", "-dh", default="dhparam2048.pem", help="Diffie/Hellman parameters path, dhparam2048.pem relative to -d by default")
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to -d by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl relative to -d by default")
@click.option("--verify-client", "-vc", type=click.Choice(['optional', 'on', 'off']))
@expand_paths()
def certidude_setup_nginx(server, site_config, tls_config, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, dhparam_path, verify_client):
    # TODO: Intelligent way of getting last IP address in the subnet

    if not os.path.exists(certificate_path):
        click.echo("As HTTPS server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)
        click.echo()
    retval = certidude_request_certificate(server, key_path, request_path,
        certificate_path, authority_path, revocations_path, common_name, org_unit,
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
@click.argument("server")
@click.argument("remote")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", help="E-mail associated with the request, none by default")
@click.option("--config", "-o",
    default="/etc/openvpn/client-to-site.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-key", default=HOSTNAME + ".key", help="Key path, %s.key relative to -d by default" % HOSTNAME)
@click.option("--request-path", "-csr", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to -d by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to -d by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to --dir by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl relative to -d by default")
@expand_paths()
def certidude_setup_openvpn_client(server, config, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, proto, remote):

    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path, revocations_path,
        common_name, org_unit, email_address,
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
@click.argument("server")
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
@click.option("--revocations-path", "-crl", default="crls/ca.pem", help="Certificate revocation list, crls/ca.pem by default")
@expand_paths()
def certidude_setup_strongswan_server(server, config, secrets, subnet, route, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, local, fqdn):
    if "." not in common_name:
        raise ValueError("Hostname has to be fully qualified!")
    if not local:
        raise ValueError("Please specify local IP address")

    if not os.path.exists(certificate_path):
        click.echo("As strongSwan server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)
        click.echo()

    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path, revocations_path,
        common_name, org_unit, email_address,
        key_usage="digitalSignature,keyEncipherment",
        extended_key_usage="serverAuth,1.3.6.1.5.5.8.2.2",
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
    click.echo("If you're running Ubuntu make sure you're not affected by #1505222")
    click.echo("https://bugs.launchpad.net/ubuntu/+source/strongswan/+bug/1505222")


@click.command("client", help="Set up strongSwan client")
@click.argument("server")
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
@click.option("--revocations-path", "-crl", default="crls/ca.pemf", help="Certificate revocation list, ca.crl relative to -d by default")
@expand_paths()
def certidude_setup_strongswan_client(server, config, secrets, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, remote, auto, dpdaction):
    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path,
        common_name, org_unit, email_address,
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
@click.argument("server") # Certidude server
@click.argument("remote") # StrongSwan gateway
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--directory", "-d", default="/etc/ipsec.d", help="Directory for keys, /etc/ipsec.d by default")
@click.option("--key-path", "-key", default="private/%s.pem" % HOSTNAME, help="Key path, private/%s.pem by default" % HOSTNAME)
@click.option("--request-path", "-csr", default="reqs/%s.pem" % HOSTNAME, help="Request path, reqs/%s.pem by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default="certs/%s.pem" % HOSTNAME, help="Certificate path, certs/%s.pem by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="cacerts/ca.pem", help="Certificate authority certificate path, cacerts/ca.pem by default")
@click.option("--revocations-path", "-crl", default="crls/ca.pem", help="Certificate revocation list, crls/ca.pem by default")
@expand_paths()
def certidude_setup_strongswan_networkmanager(server, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, remote):
    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path, revocations_path,
        common_name, org_unit, email_address,
        wait=True)

    if retval:
        return retval

    services = ConfigParser()
    if os.path.exists("/etc/certidude/services.conf"):
        services.readfp(open("/etc/certidude/services.conf"))

    endpoint = "IPSec to %s" % remote

    if services.has_section(endpoint):
        click.echo("Section %s already exists in /etc/certidude/services.conf, not reconfiguring" % endpoint)
    else:
        click.echo("Section %s added to /etc/certidude/client.conf" % endpoint)
        services.add_section(endpoint)
        services.set(endpoint, "authority", server)
        services.set(endpoint, "remote", remote)
        services.set(endpoint, "service", "network-manager/strongswan")
        services.write(open("/etc/certidude/services.conf", "w"))


@click.command("networkmanager", help="Set up OpenVPN client via NetworkManager")
@click.argument("server") # Certidude server
@click.argument("remote") # OpenVPN gateway
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, %s by default" % HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", help="E-mail associated with the request, none by default")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-key", default=HOSTNAME + ".key", help="Key path, %s.key relative to -d by default" % HOSTNAME)
@click.option("--request-path", "-csr", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to -d by default" % HOSTNAME)
@click.option("--certificate-path", "-crt", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to -d by default" % HOSTNAME)
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate path, ca.crt relative to -d by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl by default")
@expand_paths()
def certidude_setup_openvpn_networkmanager(server, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, remote):
    retval = certidude_request_certificate(server,
        key_path, request_path, certificate_path, authority_path, revocations_path,
        common_name, org_unit, email_address,
        wait=True)

    if retval:
        return retval

    services = ConfigParser()
    if os.path.exists("/etc/certidude/services.conf"):
        services.readfp(open("/etc/certidude/services.conf"))

    endpoint = "OpenVPN to %s" % remote

    if services.has_section(endpoint):
        click.echo("Section %s already exists in /etc/certidude/services.conf, not reconfiguring" % endpoint)
    else:
        click.echo("Section %s added to /etc/certidude/client.conf" % endpoint)
        services.add_section(endpoint)
        services.set(endpoint, "authority", server)
        services.set(endpoint, "remote", remote)
        services.set(endpoint, "service", "network-manager/openvpn")
        services.write(open("/etc/certidude/services.conf", "w"))


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--username", default="certidude", help="Service user account, created if necessary, 'certidude' by default")
@click.option("--static-path", default=os.path.join(os.path.dirname(__file__), "static"), help="Path to Certidude's static JS/CSS/etc")
@click.option("--kerberos-keytab", default="/etc/certidude/server.keytab", help="Kerberos keytab for using 'kerberos' authentication backend, /etc/certidude/server.keytab by default")
@click.option("--nginx-config", "-n",
    default="/etc/nginx/sites-available/certidude.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="nginx site config for serving Certidude, /etc/nginx/sites-available/certidude by default")
@click.option("--uwsgi-config", "-u",
    default="/etc/uwsgi/apps-available/certidude.ini",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="uwsgi configuration for serving Certidude API, /etc/uwsgi/apps-available/certidude.ini by default")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=FQDN, help="Common name, fully qualified hostname by default")
@click.option("--country", "-c", default=None, help="Country, none by default")
@click.option("--state", "-s", default=None, help="State or country, none by default")
@click.option("--locality", "-l", default=None, help="City or locality, none by default")
@click.option("--authority-lifetime", default=20*365, help="Authority certificate lifetime in days, 7300 days (20 years) by default")
@click.option("--certificate-lifetime", default=5*365, help="Certificate lifetime in days, 1825 days (5 years) by default")
@click.option("--revocation-list-lifetime", default=20*60, help="Revocation list lifetime in days, 1200 seconds (20 minutes) by default")
@click.option("--organization", "-o", default=None, help="Company or organization name")
@click.option("--organizational-unit", "-ou", default=None)
@click.option("--revoked-url", default=None, help="CRL distribution URL")
@click.option("--certificate-url", default=None, help="Authority certificate URL")
@click.option("--push-server", default="http://" + constants.FQDN, help="Push server, by default http://%s" % constants.FQDN)
@click.option("--email-address", default="certidude@" + FQDN, help="E-mail address of the CA")
@click.option("--directory", default=os.path.join("/var/lib/certidude", FQDN), help="Directory for authority files, /var/lib/certidude/%s/ by default" % FQDN)
@click.option("--server-flags", is_flag=True, help="Add TLS Server and IKE Intermediate extended key usage flags")
@click.option("--outbox", default="smtp://smtp.%s" % constants.DOMAIN, help="SMTP server, smtp://smtp.%s by default" % constants.DOMAIN)
def certidude_setup_authority(username, static_path, kerberos_keytab, nginx_config, uwsgi_config, parent, country, state, locality, organization, organizational_unit, common_name, directory, certificate_lifetime, authority_lifetime, revocation_list_lifetime, revoked_url, certificate_url, push_server, email_address, outbox, server_flags):

    # Expand variables
    if not revoked_url:
        revoked_url = "http://%s/api/revoked/" % common_name
    if not certificate_url:
        certificate_url = "http://%s/api/certificate/" % common_name
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")
    if not static_path.endswith("/"):
        static_path += "/"
    certidude_conf = os.path.join("/etc/certidude/server.conf")

    try:
        pwd.getpwnam("certidude")
    except KeyError:
        cmd = "adduser", "--system", "--no-create-home", "--group", "certidude"
        if subprocess.call(cmd):
            click.echo("Failed to create system user 'certidude'")
            return 255

    if not os.path.exists("/etc/certidude"):
        click.echo("Creating /etc/certidude")
        os.makedirs("/etc/certidude")

    if os.path.exists(kerberos_keytab):
        click.echo("Service principal keytab found in '%s'" % kerberos_keytab)
    else:
        click.echo("To use 'kerberos' authentication backend create service principal with:")
        click.echo()
        click.echo("  KRB5_KTNAME=FILE:%s net ads keytab add HTTP -P" % kerberos_keytab)
        click.echo("  chown %s %s" % (username, kerberos_keytab))
        click.echo()

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
        click.echo("Warning: /etc/krb5.keytab or /etc/samba/smb.conf not found, Kerberos unconfigured")

    nginx_config.write(env.get_template("nginx.conf").render(vars()))
    click.echo("Generated: %s" % nginx_config.name)
    uwsgi_config.write(env.get_template("uwsgi.ini").render(vars()))
    click.echo("Generated: %s" % uwsgi_config.name)

    if not os.path.exists("/etc/nginx/sites-enabled/certidude.conf"):
        os.symlink("../sites-available/certidude.conf", "/etc/nginx/sites-enabled/certidude.conf")
        click.echo("Symlinked %s -> /etc/nginx/sites-enabled/" % nginx_config.name)
    if not os.path.exists("/etc/uwsgi/apps-enabled/certidude.ini"):
        os.symlink("../apps-available/certidude.ini", "/etc/uwsgi/apps-enabled/certidude.ini")
        click.echo("Symlinked %s -> /etc/uwsgi/apps-enabled/" % uwsgi_config.name)
    if os.path.exists("/etc/nginx/sites-enabled/default"):
        os.unlink("/etc/nginx/sites-enabled/default")


    if not push_server:
        click.echo("Remember to install nchan instead of regular nginx!")

    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    os.setgid(gid)

    if os.path.exists(certidude_conf):
        click.echo("Configuration file %s already exists, remove to regenerate" % certidude_conf)
    else:
        os.umask(0o137)
        with open(certidude_conf, "w") as fh:
            fh.write(env.get_template("certidude.conf").render(vars()))
        click.echo("Generated %s" % certidude_conf)

    if os.path.lexists(directory):
        raise click.ClickException("CA directory %s already exists, remove to regenerate" % directory)

    click.echo("CA configuration files are saved to: {}".format(directory))

    click.echo("Generating 4096-bit RSA key...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(o, value) for o, value in (
            (NameOID.COUNTRY_NAME, country),
            (NameOID.STATE_OR_PROVINCE_NAME, state),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.ORGANIZATION_NAME, organization),
            (NameOID.COMMON_NAME, common_name),
        ) if value
    ])

    builder = x509.CertificateBuilder(
        ).subject_name(subject
        ).issuer_name(issuer
        ).public_key(key.public_key()
        ).not_valid_before(datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=authority_lifetime)
        ).serial_number(1
        ).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False), critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.RFC822Name(email_address)
            ]),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False

        )

    if server_flags:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2")]), critical=False)

    cert = builder.sign(key, hashes.SHA512(), default_backend())

    click.echo("Signing %s..." % cert.subject)

    # Create authority directory with 750 permissions
    os.umask(0o027)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Create subdirectories with 770 permissions
    os.umask(0o007)
    for subdir in ("signed", "requests", "revoked", "expired"):
        if not os.path.exists(os.path.join(directory, subdir)):
            os.mkdir(os.path.join(directory, subdir))

    # Set permission bits to 640
    os.umask(0o137)
    with open(ca_crt, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))

    # Set permission bits to 600
    os.umask(0o177)
    with open(ca_key, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption() # TODO: Implement passphrase
        ))

    click.echo()
    click.echo("Use following commands to inspect the newly created files:")
    click.echo()
    click.echo("  openssl x509 -text -noout -in %s | less" % ca_crt)
    click.echo("  openssl rsa -check -in %s" % ca_key)
    click.echo("  openssl verify -CAfile %s %s" % (ca_crt, ca_crt))
    click.echo()
    click.echo("Use following to launch privilege isolated signer processes:")
    click.echo()
    click.echo("  certidude signer spawn")
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
certidude_setup_openvpn.add_command(certidude_setup_openvpn_networkmanager)
certidude_setup.add_command(certidude_setup_authority)
certidude_setup.add_command(certidude_setup_openvpn)
certidude_setup.add_command(certidude_setup_strongswan)
certidude_setup.add_command(certidude_setup_client)
certidude_setup.add_command(certidude_setup_nginx)
certidude_request.add_command(certidude_request_spawn)
certidude_signer.add_command(certidude_signer_spawn)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_signer)
entry_point.add_command(certidude_request)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_list)
