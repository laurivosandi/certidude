# coding: utf-8

import asyncore
import click
import hashlib
import logging
import os
import pwd
import random
import re
import requests
import signal
import socket
import string
import subprocess
import sys
from configparser import ConfigParser, NoOptionError, NoSectionError
from certidude.helpers import certidude_request_certificate
from certidude.common import expand_paths, ip_address, ip_network
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from humanize import naturaltime
from jinja2 import Environment, PackageLoader
from time import sleep
from setproctitle import setproctitle
import const

env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

# http://www.mad-hacking.net/documentation/linux/security/ssl-tls/creating-ca.xml
# https://kjur.github.io/jsrsasign/
# keyUsage, extendedKeyUsage - https://www.openssl.org/docs/apps/x509v3_client_config.html
# strongSwan key paths - https://wiki.strongswan.org/projects/1/wiki/SimpleCA

# Parse command-line argument defaults from environment

USERNAME = os.environ.get("USER")
NOW = datetime.utcnow().replace(tzinfo=None)
FIRST_NAME = None
SURNAME = None
EMAIL = None

if USERNAME:
    EMAIL = USERNAME + "@" + const.FQDN

if os.getuid() >= 1000:
    _, _, _, _, gecos, _, _ = pwd.getpwnam(USERNAME)
    if " " in gecos:
        FIRST_NAME, SURNAME = gecos.split(" ", 1)
    else:
        FIRST_NAME = gecos


@click.command("request", help="Run processes for requesting certificates and configuring services")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
def certidude_request(fork):
    if not os.path.exists(const.CLIENT_CONFIG_PATH):
        click.echo("No %s!" % const.CLIENT_CONFIG_PATH)
        return 1

    if not os.path.exists(const.SERVICES_CONFIG_PATH):
        click.echo("No %s!" % const.SERVICES_CONFIG_PATH)
        return 1

    clients = ConfigParser()
    clients.readfp(open(const.CLIENT_CONFIG_PATH))

    service_config = ConfigParser()
    service_config.readfp(open(const.SERVICES_CONFIG_PATH))

    # Process directories
    run_dir = "/run/certidude"

    # Prepare signer PID-s directory
    if not os.path.exists(run_dir):
        click.echo("Creating: %s" % run_dir)
        os.makedirs(run_dir)

    for authority in clients.sections():
        try:
            endpoint_insecure = clients.getboolean(authority, "insecure")
        except NoOptionError:
            endpoint_insecure = False
        try:
            endpoint_common_name = clients.get(authority, "common name")
        except NoOptionError:
            endpoint_common_name = const.HOSTNAME
        try:
            endpoint_key_path = clients.get(authority, "key path")
        except NoOptionError:
            endpoint_key_path = "/var/lib/certidude/%s/keys/%s.pem" % (authority, const.HOSTNAME)
        try:
            endpoint_request_path = clients.get(authority, "request path")
        except NoOptionError:
            endpoint_request_path = "/var/lib/certidude/%s/requests/%s.pem" % (authority, const.HOSTNAME)
        try:
            endpoint_certificate_path = clients.get(authority, "certificate path")
        except NoOptionError:
            endpoint_certificate_path = "/var/lib/certidude/%s/signed/%s.pem" % (authority, const.HOSTNAME)
        try:
            endpoint_authority_path = clients.get(authority, "authority path")
        except NoOptionError:
            endpoint_authority_path = "/var/lib/certidude/%s/ca_crt.pem" % authority
        try:
            endpoint_revocations_path = clients.get(authority, "revocations path")
        except NoOptionError:
            endpoint_revocations_path = "/var/lib/certidude/%s/ca_crl.pem" % authority
        # TODO: Create directories automatically

        extended_key_usage_flags=[]
        try:
            endpoint_key_flags = set([j.strip() for j in clients.get(authority, "extended key usage flags").lower().split(",") if j.strip()])
        except NoOptionError:
            pass
        else:
            if "server auth" in endpoint_key_flags:
                endpoint_key_flags -= set(["server auth"])
                extended_key_usage_flags.append(ExtendedKeyUsageOID.SERVER_AUTH)
            if "ike intermediate" in endpoint_key_flags:
                endpoint_key_flags -= set(["ike intermediate"])
                extended_key_usage_flags.append(x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2"))
            if endpoint_key_flags:
                raise ValueError("Extended key usage flags %s not understood!" % endpoint_key_flags)
            # TODO: IKE Intermediate

        if clients.get(authority, "trigger") == "domain joined":
            if not os.path.exists("/etc/krb5.keytab"):
                continue
        elif clients.get(authority, "trigger") != "interface up":
            continue

        pid_path = os.path.join(run_dir, authority + ".pid")

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
        retries = 30

        while retries > 0:
            try:
                certidude_request_certificate(
                    authority,
                    endpoint_key_path,
                    endpoint_request_path,
                    endpoint_certificate_path,
                    endpoint_authority_path,
                    endpoint_revocations_path,
                    endpoint_common_name,
                    extended_key_usage_flags,
                    None,
                    insecure=endpoint_insecure,
                    autosign=True,
                    wait=True)
                break
            except requests.exceptions.Timeout:
                retries -= 1
                continue

        for endpoint in service_config.sections():
            if service_config.get(endpoint, "authority") != authority:
                continue

            click.echo("Configuring '%s'" % endpoint)
            csummer = hashlib.sha1()
            csummer.update(endpoint.encode("ascii"))
            csum = csummer.hexdigest()
            uuid = csum[:8] + "-" + csum[8:12] + "-" + csum[12:16] + "-" + csum[16:20] + "-" + csum[20:32]

            # Intranet HTTPS handled by PKCS#12 bundle generation,
            # so it will not be implemented here

            # OpenVPN set up with initscripts
            if service_config.get(endpoint, "service") == "init/openvpn":
                if os.path.exists("/etc/openvpn/%s.disabled" % endpoint) and not os.path.exists("/etc/openvpn/%s.conf" % endpoint):
                    os.rename("/etc/openvpn/%s.disabled" % endpoint, "/etc/openvpn/%s.conf" % endpoint)
                if os.path.exists("/bin/systemctl"):
                    click.echo("Re-running systemd generators for OpenVPN...")
                    os.system("systemctl daemon-reload")
                click.echo("Starting OpenVPN...")
                os.system("service openvpn start")
                continue

            # IPSec set up with initscripts
            if service_config.get(endpoint, "service") == "init/strongswan":
                from ipsecparse import loads
                config = loads(open('/etc/ipsec.conf').read())
                if config["conn"][server]["left"] == "%defaultroute":
                    config["conn"][server]["auto"] = "start" # This is client
                else:
                    config["conn"][server]["auto"] = "add" # This is server
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

            # OpenVPN set up with NetworkManager
            if service_config.get(endpoint, "service") == "network-manager/openvpn":
                nm_config = ConfigParser()
                nm_config.add_section("connection")
                nm_config.set("connection", "id", endpoint)
                nm_config.set("connection", "uuid", uuid)
                nm_config.set("connection", "type", "vpn")
                nm_config.add_section("vpn")
                nm_config.set("vpn", "service-type", "org.freedesktop.NetworkManager.openvpn")
                nm_config.set("vpn", "connection-type", "tls")
                nm_config.set("vpn", "comp-lzo", "yes")
                nm_config.set("vpn", "cert-pass-flags", "0")
                nm_config.set("vpn", "tap-dev", "no")
                nm_config.set("vpn", "remote-cert-tls", "server") # Assert TLS Server flag of X.509 certificate
                nm_config.set("vpn", "remote", service_config.get(endpoint, "remote"))
                nm_config.set("vpn", "key", endpoint_key_path)
                nm_config.set("vpn", "cert", endpoint_certificate_path)
                nm_config.set("vpn", "ca", endpoint_authority_path)
                nm_config.add_section("ipv4")
                nm_config.set("ipv4", "method", "auto")
                nm_config.set("ipv4", "never-default", "true")
                nm_config.add_section("ipv6")
                nm_config.set("ipv6", "method", "auto")

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write NetworkManager configuration
                with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as fh:
                    nm_config.write(fh)
                    click.echo("Created %s" % fh.name)
                os.system("nmcli con reload")
                continue


            # IPSec set up with NetworkManager
            elif service_config.get(endpoint, "service") == "network-manager/strongswan":
                client_config = ConfigParser()
                nm_config.add_section("connection")
                nm_config.set("connection", "id", endpoint)
                nm_config.set("connection", "uuid", uuid)
                nm_config.set("connection", "type", "vpn")
                nm_config.add_section("vpn")
                nm_config.set("vpn", "service-type", "org.freedesktop.NetworkManager.strongswan")
                nm_config.set("vpn", "encap", "no")
                nm_config.set("vpn", "virtual", "yes")
                nm_config.set("vpn", "method", "key")
                nm_config.set("vpn", "ipcomp", "no")
                nm_config.set("vpn", "address", service_config.get(endpoint, "remote"))
                nm_config.set("vpn", "userkey", endpoint_key_path)
                nm_config.set("vpn", "usercert", endpoint_certificate_path)
                nm_config.set("vpn", "certificate", endpoint_authority_path)
                nm_config.add_section("ipv4")
                nm_config.set("ipv4", "method", "auto")

                # Add routes, may need some more tweaking
                if service_config.has_option(endpoint, "route"):
                    for index, subnet in enumerate(service_config.get(endpoint, "route").split(","), start=1):
                        nm_config.set("ipv4", "route%d" % index, subnet)

                # Prevent creation of files with liberal permissions
                os.umask(0o177)

                # Write NetworkManager configuration
                with open(os.path.join("/etc/NetworkManager/system-connections", endpoint), "w") as fh:
                    nm_config.write(fh)
                    click.echo("Created %s" % fh.name)
                os.system("nmcli con reload")
                continue

            # TODO: Puppet, OpenLDAP, <insert awesomeness here>

        os.unlink(pid_path)


@click.command("client", help="Setup X.509 certificates for application")
@click.argument("server")
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, '%s' by default" % const.HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, '%s' by default" % EMAIL)
@click.option("--given-name", "-gn", default=FIRST_NAME, help="Given name of the person associted with the certificate, '%s' by default" % FIRST_NAME)
@click.option("--surname", "-sn", default=SURNAME, help="Surname of the person associted with the certificate, '%s' by default" % SURNAME)
@click.option("--key-usage", "-ku", help="Key usage attributes, none requested by default")
@click.option("--extended-key-usage", "-eku", help="Extended key usage attributes, none requested by default")
@click.option("--quiet", "-q", default=False, is_flag=True, help="Disable verbose output")
@click.option("--autosign", "-s", default=False, is_flag=True, help="Request for automatic signing if available")
@click.option("--wait", "-w", default=False, is_flag=True, help="Wait for certificate, by default return immideately")
@click.option("--key-path", "-k", default=const.HOSTNAME + ".key", help="Key path, %s.key by default" % const.HOSTNAME)
@click.option("--request-path", "-r", default=const.HOSTNAME + ".csr", help="Request path, %s.csr by default" % const.HOSTNAME)
@click.option("--certificate-path", "-c", default=const.HOSTNAME + ".crt", help="Certificate path, %s.crt by default" % const.HOSTNAME)
@click.option("--authority-path", "-a", default="ca.crt", help="Certificate authority certificate path, ca.crt by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl by default")
def certidude_setup_client(quiet, **kwargs):
    return certidude_request_certificate(**kwargs)


@click.command("server", help="Set up OpenVPN server")
@click.argument("authority")
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
def certidude_setup_openvpn_server(authority, config, subnet, route, email_address, org_unit, local, proto, port):

    # TODO: Make dirs
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

    # Create corresponding section in Certidude client configuration file
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(authority):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.HOSTNAME)
        client_config.set(authority, "subject alternative name dns", const.FQDN)
        client_config.set(authority, "extended key usage flags", "server auth")
        client_config.set(authority, "request path", "/etc/openvpn/keys/%s.csr" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/openvpn/keys/%s.key" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/openvpn/keys/%s.crt" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/openvpn/keys/ca.crt")
        client_config.set(authority, "revocations path",  "/etc/openvpn/keys/ca.crl")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))


    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "OpenVPN server %s of %s" % (const.FQDN, authority)
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, not reconfiguring" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "service", "init/openvpn")
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))

    dhparam_path = "/etc/openvpn/keys/dhparam.pem"
    if not os.path.exists(dhparam_path):
        cmd = "openssl", "dhparam", "-out", dhparam_path, "2048"
        subprocess.check_call(cmd)

    config.write("mode server\n")
    config.write("tls-server\n")
    config.write("proto %s\n" % proto)
    config.write("port %d\n" % port)
    config.write("dev tap\n")
    config.write("local %s\n" % local)
    config.write("key %s\n" % client_config.get(authority, "key path"))
    config.write("cert %s\n" % client_config.get(authority, "certificate path"))
    config.write("ca %s\n" % client_config.get(authority, "authority path"))
    config.write("dh %s\n" % dhparam_path)
    config.write("comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")
    config.write("ifconfig-pool-persist /tmp/openvpn-leases.txt\n")
    config.write("ifconfig %s 255.255.255.0\n" % subnet_first)
    config.write("server-bridge %s 255.255.255.0 %s %s\n" % (subnet_first, subnet_second, subnet_last))
    config.write("#crl-verify %s\n" % client_config.get(authority, "revocations path"))

    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude request")
    click.echo()
    click.echo("As OpenVPN server certificate needs specific key usage extensions please")
    click.echo("use following command to sign on Certidude server instead of web interface:")
    click.echo()
    click.echo("  certidude sign %s" % const.HOSTNAME)


@click.command("nginx", help="Set up nginx as HTTPS server")
@click.argument("server")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, %s by default" % const.FQDN)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--tls-config",
    default="/etc/nginx/conf.d/tls.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="TLS configuration file of nginx, /etc/nginx/conf.d/tls.conf by default")
@click.option("--site-config", "-o",
    default="/etc/nginx/sites-available/%s.conf" % const.HOSTNAME,
    type=click.File(mode="w", atomic=True, lazy=True),
    help="Site configuration file of nginx, /etc/nginx/sites-available/%s.conf by default" % const.HOSTNAME)
@click.option("--directory", "-d", default="/etc/nginx/ssl", help="Directory for keys, /etc/nginx/ssl by default")
@click.option("--key-path", "-key", default=const.HOSTNAME + ".key", help="Key path, %s.key relative to -d by default" % const.HOSTNAME)
@click.option("--request-path", "-csr", default=const.HOSTNAME + ".csr", help="Request path, %s.csr relative to -d by default" % const.HOSTNAME)
@click.option("--certificate-path", "-crt", default=const.HOSTNAME + ".crt", help="Certificate path, %s.crt relative to -d by default" % const.HOSTNAME)
@click.option("--dhparam-path", "-dh", default="dhparam2048.pem", help="Diffie/Hellman parameters path, dhparam2048.pem relative to -d by default")
@click.option("--authority-path", "-ca", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to -d by default")
@click.option("--revocations-path", "-crl", default="ca.crl", help="Certificate revocation list, ca.crl relative to -d by default")
@click.option("--verify-client", "-vc", type=click.Choice(['optional', 'on', 'off']))
@expand_paths()
def certidude_setup_nginx(authority, site_config, tls_config, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, revocations_path, dhparam_path, verify_client):
    # TODO: Intelligent way of getting last IP address in the subnet

    if not os.path.exists(certificate_path):
        click.echo("As HTTPS server certificate needs specific key usage extensions please")
        click.echo("use following command to sign on Certidude server instead of web interface:")
        click.echo()
        click.echo("  certidude sign %s" % common_name)
        click.echo()
    retval = certidude_request_certificate(authority, key_path, request_path,
        certificate_path, authority_path, revocations_path, common_name, org_unit,
        extended_key_usage_flags = [ExtendedKeyUsageOID.SERVER_AUTH],
        dns = const.FQDN, wait=True, bundle=True)

    if not os.path.exists(dhparam_path):
        cmd = "openssl", "dhparam", "-out", dhparam_path, "2048"
        subprocess.check_call(cmd)

    if retval:
        return retval

    context = globals() # Grab const.BLAH
    context.update(locals())

    if os.path.exists(site_client_config.name):
        click.echo("Configuration file %s already exists, not overwriting" % site_client_config.name)
    else:
        site_client_config.write(env.get_template("nginx-https-site.conf").render(context))
        click.echo("Generated %s" % site_client_config.name)

    if os.path.exists(tls_client_config.name):
        click.echo("Configuration file %s already exists, not overwriting" % tls_client_config.name)
    else:
        tls_client_config.write(env.get_template("nginx-tls.conf").render(context))
        click.echo("Generated %s" % tls_client_config.name)

    click.echo()
    click.echo("Inspect configuration files, enable it and start nginx service:")
    click.echo()
    click.echo("  ln -s %s /etc/nginx/sites-enabled/%s" % (
        os.path.relpath(site_client_config.name, "/etc/nginx/sites-enabled"),
        os.path.basename(site_client_config.name)))
    click.secho("  service nginx restart", bold=True)
    click.echo()


@click.command("client", help="Set up OpenVPN client")
@click.argument("authority")
@click.argument("remote")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--config", "-o",
    default="/etc/openvpn/client-to-site.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
def certidude_setup_openvpn_client(authority, remote, config, org_unit, proto):

    # Create corresponding section in Certidude client configuration file
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(authority):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.add_section(authority)
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.HOSTNAME)
        client_config.set(authority, "request path", "/etc/openvpn/keys/%s.csr" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/openvpn/keys/%s.key" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/openvpn/keys/%s.crt" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/openvpn/keys/ca.crt")
        client_config.set(authority, "revocations path",  "/etc/openvpn/keys/ca.crl")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "OpenVPN connection to %s" % remote
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, not reconfiguring" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "service", "init/openvpn")
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))

    config.write("client\n")
    config.write("remote %s\n" % remote)
    config.write("remote-cert-tls server\n")
    config.write("proto %s\n" % proto)
    config.write("dev tap\n")
    config.write("nobind\n")
    config.write("key %s\n" % client_config.get(authority, "key path"))
    config.write("cert %s\n" % client_config.get(authority, "certificate path"))
    config.write("ca %s\n" % client_config.get(authority, "authority path"))
    config.write("crl-verify %s\n" % client_config.get(authority, "revocations path"))
    config.write("comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")

    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude request")
    click.echo()
    click.echo("As OpenVPN server certificate needs specific key usage extensions please")
    click.echo("use following command to sign on Certidude server instead of web interface:")
    click.echo()
    click.echo("  certidude sign %s" % const.HOSTNAME)


@click.command("server", help="Set up strongSwan server")
@click.argument("server")
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", default=EMAIL, help="E-mail associated with the request, %s by default" % EMAIL)
@click.option("--subnet", "-sn", default=u"192.168.33.0/24", type=ip_network, help="IPsec virtual subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", type=ip_address, help="IP address associated with the certificate, none by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
def certidude_setup_strongswan_server(authority, config, secrets, subnet, route, email_address, org_unit, local, fqdn):
    if "." not in common_name:
        raise ValueError("Hostname has to be fully qualified!")
    if not local:
        raise ValueError("Please specify local IP address")

    # Create corresponding section in Certidude client configuration file
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(server):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.FQDN)
        client_config.set(authority, "subject alternative name dns", const.FQDN)
        client_config.set(authority, "extended key usage flags", "server auth, ike intermediate")
        client_config.set(authority, "request path", "/etc/ipsec.d/reqs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/ipsec.d/private/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/ipsec.d/certs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/ipsec.d/cacerts/ca.pem")
        client_config.set(authority, "authority path",  "/etc/ipsec.d/crls/ca.pem")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

    # Create corresponding section to /etc/ipsec.conf
    from ipsecparse import loads
    config = loads(open('/etc/ipsec.conf').read())
    config["conn", server] = dict(
        leftsourceip="%config",
        left=common_name,
        leftcert=certificate_path,
        leftsubnet=route.join(", "),
        right="%any",
        rightsourceip=subnet,
        keyexchange="ikev2",
        keyingtries="300",
        dpdaction=dpdaction,
        closeaction="restart",
        auto="ignore")
    with open("/etc/ipsec.conf.part", "w") as fh:
        fh.write(client_config.dumps())
    os.rename("/etc/ipsec.conf.part", "/etc/ipsec.conf")

    click.echo()
    click.echo("If you're running Ubuntu make sure you're not affected by #1505222")
    click.echo("https://bugs.launchpad.net/ubuntu/+source/strongswan/+bug/1505222")


@click.command("client", help="Set up strongSwan client")
@click.argument("server")
@click.argument("remote")
@click.option("--org-unit", "-ou", help="Organizational unit")
def certidude_setup_strongswan_client(authority, config, org_unit, remote, dpdaction):
    # Create corresponding section in /etc/certidude/client.conf
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(server):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.add_section(authority)
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.HOSTNAME)
        client_config.set(authority, "request path", "/etc/ipsec.d/reqs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/ipsec.d/private/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/ipsec.d/certs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/ipsec.d/cacerts/ca.pem")
        client_config.set(authority, "authority path",  "/etc/ipsec.d/crls/ca.pem")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

    # Create corresponding section in /etc/ipsec.conf
    from ipsecparse import loads
    config = loads(open('/etc/ipsec.conf').read())
    config["conn", server] = dict(
        leftsourceip="%config",
        left="%defaultroute",
        leftcert=certificate_path,
        rightid="%any",
        right=remote,
        rightsubnet=route,
        keyexchange="ikev2",
        keyingtries="300",
        dpdaction="restart",
        closeaction="restart",
        auto="ignore")
    with open("/etc/ipsec.conf.part", "w") as fh:
        fh.write(client_config.dumps())
    os.rename("/etc/ipsec.conf.part", "/etc/ipsec.conf")

    click.echo("Generated section %s in %s" % (authority, client_config.name))
    click.echo("Run 'certidude request' to request certificates and to enable services")


@click.command("networkmanager", help="Set up strongSwan client via NetworkManager")
@click.argument("server") # Certidude server
@click.argument("remote") # StrongSwan gateway
@click.option("--org-unit", "-ou", help="Organizational unit")
def certidude_setup_strongswan_networkmanager(server,remote,  org_unit):
    endpoint = "IPSec to %s" % remote

    # Create corresponding section in /etc/certidude/client.conf
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(server):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.add_section(authority)
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.HOSTNAME)
        client_config.set(authority, "org unit", org_unit)
        client_config.set(authority, "request path", "/etc/ipsec.d/reqs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/ipsec.d/private/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/ipsec.d/certs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/ipsec.d/cacerts/ca.pem")
        client_config.set(authority, "authority path",  "/etc/ipsec.d/crls/ca.pem")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

    # Create corresponding section in /etc/certidude/services.conf
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(authority, "authority", server)
        service_config.set(authority, "remote", remote)
        service_config.set(authority, "service", "network-manager/strongswan-client")
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))


@click.command("networkmanager", help="Set up OpenVPN client via NetworkManager")
@click.argument("server") # Certidude server
@click.argument("remote") # OpenVPN gateway
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, %s by default" % const.HOSTNAME)
@click.option("--org-unit", "-ou", help="Organizational unit")
@click.option("--email-address", "-m", help="E-mail associated with the request, none by default")
def certidude_setup_openvpn_networkmanager(authority, email_address, org_unit, remote):
    # Create corresponding section in /etc/certidude/client.conf
    client_config = ConfigParser()
    if os.path.exists(const.CLIENT_CONFIG_PATH):
        client_config.readfp(open(const.CLIENT_CONFIG_PATH))
    if client_config.has_section(server):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
    else:
        client_config.add_section(authority)
        client_config.set(authority, "trigger", "interface up")
        client_config.set(authority, "common name", const.HOSTNAME)
        client_config.set(authority, "request path", "/etc/ipsec.d/reqs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "key path", "/etc/ipsec.d/private/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "certificate path", "/etc/ipsec.d/certs/%s.pem" % const.HOSTNAME)
        client_config.set(authority, "authority path",  "/etc/ipsec.d/cacerts/ca.pem")
        client_config.set(authority, "authority path",  "/etc/ipsec.d/crls/ca.pem")
        with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
            client_config.write(fh)
        os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

    endpoint = "OpenVPN to %s" % remote

    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(authority, "authority", server)
        service_config.set(endpoint, "remote", remote)
        service_config.set(endpoint, "service", "network-manager/openvpn")
        service_config.write(open("/etc/certidude/services.conf", "w"))
        click.echo("Section %s added to /etc/certidude/client.conf" % endpoint)


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--username", default="certidude", help="Service user account, created if necessary, 'certidude' by default")
@click.option("--static-path", default=os.path.join(os.path.dirname(__file__), "static"), help="Path to Certidude's static JS/CSS/etc")
@click.option("--kerberos-keytab", default="/etc/certidude/server.keytab", help="Kerberos keytab for using 'kerberos' authentication backend, /etc/certidude/server.keytab by default")
@click.option("--nginx-config", "-n",
    default="/etc/nginx/sites-available/certidude.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="nginx site config for serving Certidude, /etc/nginx/sites-available/certidude by default")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, fully qualified hostname by default")
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
@click.option("--push-server", default="http://" + const.FQDN, help="Push server, by default http://%s" % const.FQDN)
@click.option("--email-address", default="certidude@" + const.FQDN, help="E-mail address of the CA")
@click.option("--directory", help="Directory for authority files")
@click.option("--server-flags", is_flag=True, help="Add TLS Server and IKE Intermediate extended key usage flags")
@click.option("--outbox", default="smtp://smtp.%s" % const.DOMAIN, help="SMTP server, smtp://smtp.%s by default" % const.DOMAIN)
def certidude_setup_authority(username, static_path, kerberos_keytab, nginx_config, parent, country, state, locality, organization, organizational_unit, common_name, directory, certificate_lifetime, authority_lifetime, revocation_list_lifetime, revoked_url, certificate_url, push_server, email_address, outbox, server_flags):

    if not directory:
        if os.getuid():
            directory = os.path.join(os.path.expanduser("~/.certidude"), const.FQDN)
        else:
            directory = os.path.join("/var/lib/certidude", const.FQDN)

    click.echo("Using fully qualified hostname: %s" % common_name)

    # Expand variables
    if not revoked_url:
        revoked_url = "http://%s/api/revoked/" % common_name
    if not certificate_url:
        certificate_url = "http://%s/api/certificate/" % common_name
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")

    if not static_path.endswith("/"):
        static_path += "/"

    if os.getuid() == 0:
        try:
            pwd.getpwnam("certidude")
        except KeyError:
            cmd = "adduser", "--system", "--no-create-home", "--group", "certidude"
            if subprocess.call(cmd):
                click.echo("Failed to create system user 'certidude'")
                return 255

        if os.path.exists(kerberos_keytab):
            click.echo("Service principal keytab found in '%s'" % kerberos_keytab)
        else:
            click.echo("To use 'kerberos' authentication backend join the domain and create service principal with:")
            click.echo()
            click.echo("  KRB5_KTNAME=FILE:%s net ads keytab add HTTP -P" % kerberos_keytab)
            click.echo("  chown %s %s" % (username, kerberos_keytab))
            click.echo()

        if os.path.exists("/etc/krb5.keytab") and os.path.exists("/etc/samba/smb.conf"):
            # Fetch Kerberos ticket for system account
            cp = ConfigParser()
            cp.read("/etc/samba/smb.conf")
            realm = cp.get("global", "realm")
            domain = realm.lower()
            name = cp.get("global", "netbios name")

            base = ",".join(["dc=" + j for j in domain.split(".")])
            with open("/etc/cron.hourly/certidude", "w") as fh:
                fh.write(env.get_template("ldap-ticket-renewal.sh").render(vars()))
            os.chmod("/etc/cron.hourly/certidude", 0o755)
            click.echo("Created /etc/cron.hourly/certidude for automatic LDAP service ticket renewal, inspect and adjust accordingly")
            os.system("/etc/cron.hourly/certidude")
        else:
            click.echo("Warning: /etc/krb5.keytab or /etc/samba/smb.conf not found, Kerberos unconfigured")


        working_directory = os.path.realpath(os.path.dirname(__file__))
        certidude_path = sys.argv[0]

        if not os.path.exists("/etc/nginx"):
            click.echo("Directory /etc/nginx does not exist, hence not creating nginx configuration")
            listen = "0.0.0.0"
            port = "80"
        else:
            nginx_client_config.write(env.get_template("nginx.conf").render(vars()))
            click.echo("Generated: %s" % nginx_client_config.name)
            if not os.path.exists("/etc/nginx/sites-enabled/certidude.conf"):
                os.symlink("../sites-available/certidude.conf", "/etc/nginx/sites-enabled/certidude.conf")
                click.echo("Symlinked %s -> /etc/nginx/sites-enabled/" % nginx_client_config.name)
            if os.path.exists("/etc/nginx/sites-enabled/default"):
                os.unlink("/etc/nginx/sites-enabled/default")
            if not push_server:
                click.echo("Remember to install nchan instead of regular nginx!")

        if os.path.exists("/etc/systemd"):
            if os.path.exists("/etc/systemd/system/certidude.service"):
                click.echo("File /etc/systemd/system/certidude.service already exists, remove to regenerate")
            else:
                with open("/etc/systemd/system/certidude.service", "w") as fh:
                    fh.write(env.get_template("systemd.service").render(vars()))
                click.echo("File /etc/systemd/system/certidude.service created")
        else:
            NotImplemented # No systemd

        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
        os.setgid(gid)
    else:
        click.echo("Not root, skipping user and system config creation")

    if not os.path.exists(const.CONFIG_DIR):
        click.echo("Creating %s" % const.CONFIG_DIR)
        os.makedirs(const.CONFIG_DIR)

    if os.path.exists(const.CONFIG_PATH):
        click.echo("Configuration file %s already exists, remove to regenerate" % const.CONFIG_PATH)
    else:
        os.umask(0o137)
        push_token = "".join([random.choice(string.ascii_letters + string.digits) for j in range(0,32)])
        with open(const.CONFIG_PATH, "w") as fh:
            fh.write(env.get_template("certidude-server.conf").render(vars()))
        click.echo("Generated %s" % const.CONFIG_PATH)

    if os.path.lexists(directory):
        click.echo("CA directory %s already exists, remove to regenerate" % directory)
    else:
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
    click.echo("Use following command to serve CA read-only:")
    click.echo()
    click.echo("  certidude serve")


@click.command("users", help="List users")
def certidude_users():
    from certidude.user import User
    admins = set(User.objects.filter_admins())
    for user in User.objects.all():
        print "%s;%s;%s;%s;%s" % (
            "admin" if user in admins else "user",
            user.name, user.given_name, user.surname, user.mail)


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
    from certidude import authority, config
    request = authority.get_request(common_name)

    # Use signer if this is regular client CSR
    if request.signable:
        # Sign via signer process
        cert = authority.sign(request)

    # Sign directly if it's eg. TLS server CSR
    else:
        # Load CA private key and certificate
        private_key = serialization.load_pem_private_key(
            open(config.AUTHORITY_PRIVATE_KEY_PATH).read(),
            password=None, # TODO: Ask password for private key?
            backend=default_backend())
        authority_certificate = x509.load_pem_x509_certificate(
            open(config.AUTHORITY_CERTIFICATE_PATH).read(),
            backend=default_backend())

        # Drop privileges
        # to use LDAP service ticket to read usernames of the admins group
        # in order to send e-mail
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

        # Sign directly using private key
        cert = authority.sign2(request, private_key, authority_certificate,
            overwrite, True, lifetime)


@click.command("serve", help="Run server")
@click.option("-p", "--port", default=8080 if os.getuid() else 80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
def certidude_serve(port, listen):
    from certidude.signer import SignServer
    from certidude import const
    click.echo("Using configuration from: %s" % const.CONFIG_PATH)


    from certidude import config

    # Fetch UID, GID of certidude user
    import pwd
    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    restricted_groups = []
    restricted_groups.append(gid)

    """
    Spawn signer process
    """

    child_pid = os.fork()

    if child_pid:
        pass
    else:
        click.echo("Signer process spawned with PID %d at %s" % (os.getpid(), const.SIGNER_SOCKET_PATH))
        setproctitle("[signer]")

        with open(const.SIGNER_PID_PATH, "w") as fh:
            fh.write("%d\n" % os.getpid())

        logging.basicConfig(
            filename=const.SIGNER_LOG_PATH,
            level=logging.INFO)

        os.umask(0o007)
        server = SignServer()

        # Drop privileges
        if not os.getuid():
            os.chown(const.SIGNER_SOCKET_PATH, uid, gid)
            os.chmod(const.SIGNER_SOCKET_PATH, 0770)

            click.echo("Dropping privileges of signer")
            _, _, uid, gid, gecos, root, shell = pwd.getpwnam("nobody")
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        else:
            click.echo("Not dropping privileges of signer process")

        asyncore.loop()
        return


    click.echo("Users subnets: %s" %
        ", ".join([str(j) for j in config.USER_SUBNETS]))
    click.echo("Administrative subnets: %s" %
        ", ".join([str(j) for j in config.ADMIN_SUBNETS]))
    click.echo("Auto-sign enabled for following subnets: %s" %
        ", ".join([str(j) for j in config.AUTOSIGN_SUBNETS]))
    click.echo("Request submissions allowed from following subnets: %s" %
        ", ".join([str(j) for j in config.REQUEST_SUBNETS]))

    logging.basicConfig(
        filename=const.SERVER_LOG_PATH,
        level=logging.DEBUG)

    click.echo("Serving API at %s:%d" % (listen, port))
    from wsgiref.simple_server import make_server, WSGIServer
    from SocketServer import ThreadingMixIn, ForkingMixIn
    from certidude.api import certidude_app, StaticResource

    class ThreadingWSGIServer(ForkingMixIn, WSGIServer):
        pass

    click.echo("Listening on %s:%d" % (listen, port))

    app = certidude_app()
    app.add_sink(StaticResource(os.path.join(os.path.dirname(__file__), "static")))

    httpd = make_server(listen, port, app, ThreadingWSGIServer)


    """
    Drop privileges
    """

    if os.getuid() == 0:

        # Initialize LDAP service ticket
        if os.path.exists("/etc/cron.hourly/certidude"):
            os.system("/etc/cron.hourly/certidude")

        # Drop privileges
        if config.AUTHENTICATION_BACKENDS == {"pam"}:
            # PAM needs access to /etc/shadow
            import grp
            name, passwd, num, mem = grp.getgrnam("shadow")
            click.echo("Adding current user to shadow group due to PAM authentication backend")
            restricted_groups.append(num)

        os.setgroups(restricted_groups)
        os.setgid(gid)
        os.setuid(uid)

        click.echo("Switched to user %s (uid=%d, gid=%d); member of groups %s" %
            ("certidude", os.getuid(), os.getgid(), ", ".join([str(j) for j in os.getgroups()])))

        os.umask(0o007)


    # Set up log handlers
    log_handlers = []

    if config.LOGGING_BACKEND == "sql":
        from certidude.mysqllog import LogHandler
        from certidude.api.log import LogResource
        uri = config.cp.get("logging", "database")
        log_handlers.append(LogHandler(uri))
        app.add_route("/api/log/", LogResource(uri))
    elif config.LOGGING_BACKEND == "syslog":
        from logging.handlers import SyslogHandler
        log_handlers.append(SysLogHandler())
        # Browsing syslog via HTTP is obviously not possible out of the box
    elif config.LOGGING_BACKEND:
        raise ValueError("Invalid logging.backend = %s" % config.LOGGING_BACKEND)

    if config.PUSH_PUBLISH:
        from certidude.push import PushLogHandler
        log_handlers.append(PushLogHandler())

    for facility in "api", "cli":
        logger = logging.getLogger(facility)
        logger.setLevel(logging.DEBUG)
        for handler in log_handlers:
            logger.addHandler(handler)

    import atexit

    def exit_handler():
        logging.getLogger("cli").debug("Shutting down Certidude")

    atexit.register(exit_handler)

    logging.getLogger("cli").debug("Started Certidude at %s", const.FQDN)
    print "Ready"
    httpd.serve_forever()

@click.group("strongswan", help="strongSwan helpers")
def certidude_setup_strongswan(): pass

@click.group("openvpn", help="OpenVPN helpers")
def certidude_setup_openvpn(): pass

@click.group("setup", help="Getting started section")
def certidude_setup(): pass

@click.group("signer", help="Signer process management")
def certidude_signer(): pass

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
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_signer)
entry_point.add_command(certidude_request)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_list)
entry_point.add_command(certidude_users)

if __name__ == "__main__":
    entry_point()
