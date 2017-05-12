# coding: utf-8

import asyncore
import click
import hashlib
import logging
import os
import random
import re
import signal
import socket
import string
import subprocess
import sys
from configparser import ConfigParser, NoOptionError, NoSectionError
from certidude.helpers import certidude_request_certificate
from certidude.common import ip_address, ip_network, apt, rpm, pip, drop_privileges
from datetime import datetime, timedelta
from time import sleep
import const

logger = logging.getLogger(__name__)

# http://www.mad-hacking.net/documentation/linux/security/ssl-tls/creating-ca.xml
# https://kjur.github.io/jsrsasign/
# keyUsage, extendedKeyUsage - https://www.openssl.org/docs/apps/x509v3_client_config.html
# strongSwan key paths - https://wiki.strongswan.org/projects/1/wiki/SimpleCA

# Parse command-line argument defaults from environment

NOW = datetime.utcnow().replace(tzinfo=None)

def fqdn_required(func):
    def wrapped(**args):
        common_name = args.get("common_name")
        if "." in common_name:
            logger.info("Using fully qualified hostname %s" % common_name)
        else:
            raise ValueError("Fully qualified hostname not specified as common name, make sure hostname -f works")
        return func(**args)
    return wrapped

def setup_client(prefix="client_", dh=False):
    # Create section in /etc/certidude/client.conf
    def wrapper(func):
        def wrapped(**arguments):
            from certidude import const
            common_name = arguments.get("common_name")
            authority = arguments.get("authority")
            b = os.path.join(const.STORAGE_PATH, authority)
            if dh:
                path = os.path.join(const.STORAGE_PATH, "dh.pem")
                if not os.path.exists(path):
                    rpm("openssl")
                    apt("openssl")
                    cmd = "openssl", "dhparam", "-out", path, ("1024" if os.getenv("TRAVIS") else "2048")
                    subprocess.check_call(cmd)
                arguments["dhparam_path"] = path

            # Create corresponding section in Certidude client configuration file
            client_config = ConfigParser()
            if os.path.exists(const.CLIENT_CONFIG_PATH):
                client_config.readfp(open(const.CLIENT_CONFIG_PATH))
            if client_config.has_section(authority):
                click.echo("Section '%s' already exists in %s, remove to regenerate" % (authority, const.CLIENT_CONFIG_PATH))
            else:
                client_config.add_section(authority)
                client_config.set(authority, "trigger", "interface up")
                client_config.set(authority, "common name", common_name)
                client_config.set(authority, "request path", os.path.join(b, prefix + "req.pem"))
                client_config.set(authority, "key path", os.path.join(b, prefix + "key.pem"))
                client_config.set(authority, "certificate path", os.path.join(b, prefix + "cert.pem"))
                client_config.set(authority, "authority path",  os.path.join(b, "ca_cert.pem"))
                client_config.set(authority, "revocations path",  os.path.join(b, "ca_crl.pem"))
                with open(const.CLIENT_CONFIG_PATH + ".part", 'wb') as fh:
                    client_config.write(fh)
                os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
                click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

            for j in ("key", "request", "certificate", "authority", "revocations"):
                arguments["%s_path" % j] = client_config.get(authority, "%s path" % j)

            return func(**arguments)
        return wrapped
    return wrapper


@click.command("request", help="Run processes for requesting certificates and configuring services")
@click.option("-k", "--system-keytab-required", default=False, is_flag=True, help="Offer system keytab for auth")
@click.option("-r", "--renew", default=False, is_flag=True, help="Renew now")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
@click.option("-nw", "--no-wait", default=False, is_flag=True, help="Return immideately if server doesn't autosign")
def certidude_request(fork, renew, no_wait, system_keytab_required):
    # Here let's try to avoid compiling packages from scratch
    rpm("openssl") or \
    apt("openssl python-cryptography python-jinja2") or \
    pip("cryptography jinja2")

    import requests
    from jinja2 import Environment, PackageLoader
    env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

    if not os.path.exists(const.CLIENT_CONFIG_PATH):
        click.echo("No %s!" % const.CLIENT_CONFIG_PATH)
        return 1

    clients = ConfigParser()
    clients.readfp(open(const.CLIENT_CONFIG_PATH))

    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))

    # Process directories
    if not os.path.exists(const.RUN_DIR):
        click.echo("Creating: %s" % const.RUN_DIR)
        os.makedirs(const.RUN_DIR)

    context = globals()
    context.update(locals())

    if not os.path.exists("/etc/systemd/system/certidude.timer"):
        click.echo("Creating systemd timer...")
        with open("/etc/systemd/system/certidude.timer", "w") as fh:
            fh.write(env.get_template("client/certidude.timer").render(context))
    if not os.path.exists("/etc/systemd/system/certidude.service"):
        click.echo("Creating systemd service...")
        with open("/etc/systemd/system/certidude.service", "w") as fh:
            fh.write(env.get_template("client/certidude.service").render(context))


    for authority in clients.sections():
        try:
            endpoint_renewal_overlap = clients.getint(authority, "renewal overlap")
        except NoOptionError:
            endpoint_renewal_overlap = None
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

        if clients.get(authority, "trigger") == "domain joined":
            system_keytab_required = True
        elif clients.get(authority, "trigger") != "interface up":
            continue

        if system_keytab_required:
            # Stop further processing if command line argument said so or trigger expects domain membership
            if not os.path.exists("/etc/krb5.keytab"):
                continue

        pid_path = os.path.join(const.RUN_DIR, authority + ".pid")

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
                    system_keytab_required,
                    endpoint_key_path,
                    endpoint_request_path,
                    endpoint_certificate_path,
                    endpoint_authority_path,
                    endpoint_revocations_path,
                    endpoint_common_name,
                    endpoint_renewal_overlap,
                    insecure=endpoint_insecure,
                    autosign=True,
                    wait=not no_wait,
                    renew=renew)
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
                if not os.path.exists("/etc/systemd/system/openvpn-reconnect.service"):
                    with open("/etc/systemd/system/openvpn-reconnect.service", "wb") as fh:
                        fh.write(env.get_template("client/openvpn-reconnect.service").render(context))
                    click.echo("Created /etc/systemd/system/openvpn-reconnect.service")
                click.echo("Starting OpenVPN...")
                os.system("service openvpn start")
                continue

            # IPSec set up with initscripts
            if service_config.get(endpoint, "service") == "init/strongswan":
                from ipsecparse import loads
                config = loads(open("%s/ipsec.conf" % const.STRONGSWAN_PREFIX).read())
                for section_type, section_name in config:
                    # Identify correct ipsec.conf section by leftcert
                    if section_type != "conn":
                        continue
                    if config[section_type,section_name]["leftcert"] != endpoint_certificate_path:
                        continue

                    if config[section_type,section_name].get("left", "") == "%defaultroute":
                        config[section_type,section_name]["auto"] = "start" # This is client
                    elif config[section_type,section_name].get("leftsourceip", ""):
                        config[section_type,section_name]["auto"] = "add" # This is server
                    else:
                        config[section_type,section_name]["auto"] = "route" # This is site-to-site tunnel

                    with open("%s/ipsec.conf.part" % const.STRONGSWAN_PREFIX, "w") as fh:
                        fh.write(config.dumps())
                    os.rename(
                        "%s/ipsec.conf.part" % const.STRONGSWAN_PREFIX,
                        "%s/ipsec.conf" % const.STRONGSWAN_PREFIX)
                    break

                # Attempt to reload config or start if it's not running
                if os.path.exists("/usr/sbin/strongswan"): # wtf fedora
                    if os.system("strongswan update"):
                        os.system("strongswan start")
                else:
                    if os.system("ipsec update"):
                        os.system("ipsec start")

                continue

            # OpenVPN set up with NetworkManager
            if service_config.get(endpoint, "service") == "network-manager/openvpn":
                try:
                    endpoint_port = service_config.getint(endpoint, "port")
                except NoOptionError:
                    endpoint_port = 1194
                try:
                    endpoint_proto = service_config.get(endpoint, "proto")
                except NoOptionError:
                    endpoint_proto = "udp"
                # NetworkManager-strongswan-gnome
                nm_config_path = os.path.join("/etc/NetworkManager/system-connections", endpoint)
                if os.path.exists(nm_config_path):
                    click.echo("Not creating %s, remove to regenerate" % nm_config_path)
                    continue
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
                nm_config.set("vpn", "port", str(endpoint_port))
                if endpoint_proto == "tcp":
                    nm_config.set("vpn", "proto-tcp", "yes")
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
                with open(nm_config_path, "w") as fh:
                    nm_config.write(fh)
                    click.echo("Created %s" % nm_config_path)
                if os.path.exists("/run/NetworkManager"):
                    os.system("nmcli con reload")
                continue


            # IPSec set up with NetworkManager
            elif service_config.get(endpoint, "service") == "network-manager/strongswan":
                client_config = ConfigParser()
                nm_config = ConfigParser()
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
                if os.path.exists("/run/NetworkManager"):
                    os.system("nmcli con reload")
                continue

            # TODO: Puppet, OpenLDAP, <insert awesomeness here>
            click.echo("Unknown service: %s" % service_config.get(endpoint, "service"))
        os.unlink(pid_path)


@click.command("server", help="Set up OpenVPN server")
@click.argument("authority")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, %s by default" % const.FQDN)
@click.option("--subnet", "-s", default="192.168.33.0/24", type=ip_network, help="OpenVPN subnet, 192.168.33.0/24 by default")
@click.option("--local", "-l", default="0.0.0.0", help="OpenVPN listening address, defaults to all interfaces")
@click.option("--port", "-p", default=1194, type=click.IntRange(1,60000), help="OpenVPN listening port, 1194 by default")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@click.option("--config", "-o",
    default="/etc/openvpn/site-to-client.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@fqdn_required
@setup_client(prefix="server_", dh=True)
def certidude_setup_openvpn_server(authority, common_name, config, subnet, route, local, proto, port, **paths):
    # Install dependencies
    apt("openvpn")
    rpm("openvpn")

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "OpenVPN server %s of %s" % (common_name, authority)
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

    authority_hostname = authority.split(".")[0]
    config.write("server %s %s\n" % (subnet.network_address, subnet.netmask))
    config.write("dev tun-%s\n" % authority_hostname)
    config.write("proto %s\n" % proto)
    config.write("port %d\n" % port)
    config.write("local %s\n" % local)
    config.write("key %s\n" % paths.get("key_path"))
    config.write("cert %s\n" % paths.get("certificate_path"))
    config.write("ca %s\n" % paths.get("authority_path"))
    config.write("crl-verify %s\n" % paths.get("revocations_path"))
    config.write("dh %s\n" % paths.get("dhparam_path"))
    config.write("comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")
    config.write("#ifconfig-pool-persist /tmp/openvpn-leases.txt\n")


    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude request")


@click.command("nginx", help="Set up nginx as HTTPS server")
@click.argument("authority")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, %s by default" % const.FQDN)
@click.option("--tls-config",
    default="/etc/nginx/conf.d/tls.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="TLS configuration file of nginx, /etc/nginx/conf.d/tls.conf by default")
@click.option("--site-config", "-o",
    default="/etc/nginx/sites-available/%s.conf" % const.HOSTNAME,
    type=click.File(mode="w", atomic=True, lazy=True),
    help="Site configuration file of nginx, /etc/nginx/sites-available/%s.conf by default" % const.HOSTNAME)
@click.option("--verify-client", "-vc", default="optional", type=click.Choice(['optional', 'on', 'off']))
@fqdn_required
@setup_client(prefix="server_", dh=True)
def certidude_setup_nginx(authority, common_name, site_config, tls_config, verify_client, **paths):

    apt("nginx")
    rpm("nginx")
    from jinja2 import Environment, PackageLoader
    env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

    context = globals() # Grab const.BLAH
    context.update(locals())
    context.update(paths)

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
    click.echo("  service nginx restart")
    click.echo()


@click.command("client", help="Set up OpenVPN client")
@click.argument("authority")
@click.argument("remote")
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, %s by default" % const.HOSTNAME)
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--config", "-o",
    default="/etc/openvpn/client-to-site.conf", # TODO: created initially disabled conf
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@setup_client()
def certidude_setup_openvpn_client(authority, remote, common_name, config, proto, **paths):
    # Install dependencies
    apt("openvpn")
    rpm("openvpn")


    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "OpenVPN to %s" % remote
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, not reconfiguring" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "service", "init/openvpn")
        service_config.set(endpoint, "remote", remote)
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))

    config.write("client\n")
    config.write("remote %s\n" % remote)
    config.write("remote-cert-tls server\n")
    config.write("proto %s\n" % proto)
    config.write("dev tun-%s\n" % remote.split(".")[0])
    config.write("nobind\n")
    config.write("key %s\n" % paths.get("key_path"))
    config.write("cert %s\n" % paths.get("certificate_path"))
    config.write("ca %s\n" % paths.get("authority_path"))
    config.write("crl-verify %s\n" % paths.get("revocations_path"))
    config.write("comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")
    config.write("up /etc/openvpn/update-resolv-conf\n")
    config.write("down /etc/openvpn/update-resolv-conf\n")

    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude request")


@click.command("server", help="Set up strongSwan server")
@click.argument("authority")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, %s by default" % const.FQDN)
@click.option("--subnet", "-sn", default=u"192.168.33.0/24", type=ip_network, help="IPsec virtual subnet, 192.168.33.0/24 by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@fqdn_required
@setup_client(prefix="server_")
def certidude_setup_strongswan_server(authority, common_name, subnet, route, **paths):
    # Install dependencies
    apt("strongswan")
    rpm("strongswan")
    pip("ipsecparse")

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "IPsec gateway for %s" % authority
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, not reconfiguring" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "service", "init/strongswan")
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))

    # Create corresponding section to /etc/ipsec.conf
    from ipsecparse import loads
    ipsec_conf = loads(open("%s/ipsec.conf" % const.STRONGSWAN_PREFIX).read())
    ipsec_conf["ca", authority] = dict(
        auto="add",
        cacert=paths.get("authority_path"))
    ipsec_conf["conn", authority] = dict(
        leftcert=paths.get("certificate_path"),
        leftsubnet=",".join(route),
        right="%any",
        rightsourceip=str(subnet),
        closeaction="restart",
        auto="ignore")
    with open("%s/ipsec.conf" % const.STRONGSWAN_PREFIX, "w") as fh:
        fh.write(ipsec_conf.dumps())
    with open("%s/ipsec.secrets" % const.STRONGSWAN_PREFIX, "a") as fh:
        fh.write(": RSA %s\n" % paths.get("key_path"))
    if os.path.exists("/etc/apparmor.d/local"):
        with open("/etc/apparmor.d/local/usr.lib.ipsec.charon", "w") as fh:
            fh.write(os.path.join(const.STORAGE_PATH, "**") + " r,\n") # TODO: dedup!

    click.echo()
    click.echo("If you're running Ubuntu make sure you're not affected by #1505222")
    click.echo("https://bugs.launchpad.net/ubuntu/+source/strongswan/+bug/1505222")


@click.command("client", help="Set up strongSwan client")
@click.argument("authority")
@click.argument("remote")
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, %s by default" % const.HOSTNAME)
@setup_client()
def certidude_setup_strongswan_client(authority, remote, common_name, **paths):
    # Install dependencies
    apt("strongswan") or rpm("strongswan")
    pip("ipsecparse")

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "IPsec connection to %s" % remote
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, not reconfiguring" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "service", "init/strongswan")
        service_config.set(endpoint, "remote", remote)
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))

    # Create corresponding section in /etc/ipsec.conf
    from ipsecparse import loads
    ipsec_conf = loads(open('%s/ipsec.conf' % const.STRONGSWAN_PREFIX).read())
    ipsec_conf["ca", authority] = dict(
        auto="add",
        cacert=paths.get("authority_path"))
    ipsec_conf["conn", remote] = dict(
        leftsourceip="%config",
        left="%defaultroute",
        leftcert=paths.get("certificate_path"),
        rightid="%any",
        right=remote,
        rightsubnet="0.0.0.0/0", # To allow anything suggested by gateway
        keyexchange="ikev2",
        keyingtries="300",
        dpdaction="restart",
        closeaction="restart",
        auto="ignore")
    with open("%s/ipsec.conf" % const.STRONGSWAN_PREFIX, "w") as fh:
        fh.write(ipsec_conf.dumps())
    with open("%s/ipsec.secrets" % const.STRONGSWAN_PREFIX, "a") as fh:
        fh.write(": RSA %s\n" % paths.get("key_path"))
    if os.path.exists("/etc/apparmor.d/local"):
        with open("/etc/apparmor.d/local/usr.lib.ipsec.charon", "w") as fh:
            fh.write(os.path.join(const.STORAGE_PATH, "**") + " r,\n")

    click.echo("Generated section %s in %s" % (authority, const.CLIENT_CONFIG_PATH))
    click.echo("Run 'certidude request' to request certificates and to enable services")


@click.command("networkmanager", help="Set up strongSwan client via NetworkManager")
@click.argument("authority") # Certidude server
@click.argument("remote") # StrongSwan gateway
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, %s by default" % const.HOSTNAME)
@setup_client()
def certidude_setup_strongswan_networkmanager(authority, remote, common_name, **paths):
    # Install dependencies
    apt("network-manager strongswan-nm")
    rpm("NetworkManager NetworkManager-tui NetworkManager-strongswan-gnome")

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "IPSec to %s" % remote
    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "remote", remote)
        service_config.set(endpoint, "service", "network-manager/strongswan")
        with open(const.SERVICES_CONFIG_PATH + ".part", 'wb') as fh:
            service_config.write(fh)
        os.rename(const.SERVICES_CONFIG_PATH + ".part", const.SERVICES_CONFIG_PATH)
        click.echo("Section '%s' added to %s" % (endpoint, const.SERVICES_CONFIG_PATH))


@click.command("networkmanager", help="Set up OpenVPN client via NetworkManager")
@click.argument("authority")
@click.argument("remote") # OpenVPN gateway
@click.option("--common-name", "-cn", default=const.HOSTNAME, help="Common name, %s by default" % const.HOSTNAME)
@setup_client()
def certidude_setup_openvpn_networkmanager(authority, remote, common_name, **paths):
    apt("network-manager network-manager-openvpn-gnome")
    rpm("NetworkManager NetworkManager-tui NetworkManager-openvpn-gnome")

    # Create corresponding section in /etc/certidude/services.conf
    endpoint = "OpenVPN to %s" % remote

    service_config = ConfigParser()
    if os.path.exists(const.SERVICES_CONFIG_PATH):
        service_config.readfp(open(const.SERVICES_CONFIG_PATH))
    if service_config.has_section(endpoint):
        click.echo("Section '%s' already exists in %s, remove to regenerate" % (endpoint, const.SERVICES_CONFIG_PATH))
    else:
        service_config.add_section(endpoint)
        service_config.set(endpoint, "authority", authority)
        service_config.set(endpoint, "remote", remote)
        service_config.set(endpoint, "service", "network-manager/openvpn")
        service_config.write(open("/etc/certidude/services.conf", "w"))
        click.echo("Section %s added to /etc/certidude/client.conf" % endpoint)


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--username", default="certidude", help="Service user account, created if necessary, 'certidude' by default")
@click.option("--kerberos-keytab", default="/etc/certidude/server.keytab", help="Kerberos keytab for using 'kerberos' authentication backend, /etc/certidude/server.keytab by default")
@click.option("--nginx-config", "-n",
    default="/etc/nginx/sites-available/certidude.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="nginx site config for serving Certidude, /etc/nginx/sites-available/certidude by default")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, fully qualified hostname by default")
@click.option("--country", "-c", default=None, help="Country, none by default")
@click.option("--state", "-s", default=None, help="State or country, none by default")
@click.option("--locality", "-l", default=None, help="City or locality, none by default")
@click.option("--authority-lifetime", default=20*365, help="Authority certificate lifetime in days, 20 years by default")
@click.option("--organization", "-o", default=None, help="Company or organization name")
@click.option("--organizational-unit", "-ou", default=None)
@click.option("--push-server", help="Push server, by default http://%s" % const.FQDN)
@click.option("--directory", help="Directory for authority files")
@click.option("--server-flags", is_flag=True, help="Add TLS Server and IKE Intermediate extended key usage flags")
@click.option("--outbox", default="smtp://smtp.%s" % const.DOMAIN, help="SMTP server, smtp://smtp.%s by default" % const.DOMAIN)
@fqdn_required
def certidude_setup_authority(username, kerberos_keytab, nginx_config, country, state, locality, organization, organizational_unit, common_name, directory, authority_lifetime, push_server, outbox, server_flags):
    # Install only rarely changing stuff from OS package management
    apt("python-setproctitle cython python-dev libkrb5-dev libffi-dev libssl-dev")
    apt("python-mimeparse python-markdown python-xattr python-jinja2 python-cffi")
    apt("python-ldap software-properties-common libsasl2-modules-gssapi-mit")
    pip("gssapi falcon cryptography humanize ipaddress simplepam humanize requests pyopenssl")
    click.echo("Software dependencies installed")

    if not os.path.exists("/etc/apt/sources.list.d/nginx-stable-trusty.list"):
        os.system("add-apt-repository -y ppa:nginx/stable")
        os.system("apt-get update")
    if not os.path.exists("/usr/lib/nginx/modules/ngx_nchan_module.so"):
        os.system("apt-get install -y libnginx-mod-nchan")
    if not os.path.exists("/usr/sbin/nginx"):
        os.system("apt-get install -y nginx")

    import pwd
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jinja2 import Environment, PackageLoader
    env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

    # Generate secret for tokens
    token_secret = ''.join(random.choice(string.letters + string.digits + '!@#$%^&*()') for i in range(50))

    template_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
    click.echo("Using templates from %s" % template_path)

    if not directory:
        directory = os.path.join("/var/lib/certidude", common_name)
    click.echo("Placing authority files in %s" % directory)

    certificate_url = "http://%s/api/certificate/" % common_name
    click.echo("Setting CA certificate URL to %s" % certificate_url)

    revoked_url = "http://%s/api/revoked/" % common_name
    click.echo("Setting revocation list URL to %s" % revoked_url)

    # Expand variables
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")

    try:
        pwd.getpwnam("certidude")
        click.echo("User 'certidude' already exists")
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
        if not os.path.exists("/etc/cron.hourly/certidude"):
            with open("/etc/cron.hourly/certidude", "w") as fh:
                fh.write(env.get_template("server/cronjob").render(vars()))
            os.chmod("/etc/cron.hourly/certidude", 0o755)
            click.echo("Created /etc/cron.hourly/certidude for automatic LDAP service ticket renewal, inspect and adjust accordingly")
        os.system("/etc/cron.hourly/certidude")
    else:
        click.echo("Warning: /etc/krb5.keytab or /etc/samba/smb.conf not found, Kerberos unconfigured")

    static_path = os.path.join(os.path.realpath(os.path.dirname(__file__)), "static")
    certidude_path = sys.argv[0]

    # Push server config generation
    if os.path.exists("/etc/nginx"):
        listen = "127.0.1.1"
        port = "8080"
        click.echo("Generating: %s" % nginx_config.name)
        nginx_config.write(env.get_template("server/nginx.conf").render(vars()))
        nginx_config.close()
        if not os.path.exists("/etc/nginx/sites-enabled/certidude.conf"):
            os.symlink("../sites-available/certidude.conf", "/etc/nginx/sites-enabled/certidude.conf")
            click.echo("Symlinked %s -> /etc/nginx/sites-enabled/" % nginx_config.name)
        if os.path.exists("/etc/nginx/sites-enabled/default"):
            os.unlink("/etc/nginx/sites-enabled/default")
        os.system("service nginx restart")
    else:
        click.echo("Directory /etc/nginx does not exist, hence not creating nginx configuration")
        click.echo("Remember to install/configure nchan capable nginx instead of regular nginx!")
        listen = "0.0.0.0"
        port = "80"

    if os.path.exists("/etc/systemd"):
        if os.path.exists("/etc/systemd/system/certidude.service"):
            click.echo("File /etc/systemd/system/certidude.service already exists, remove to regenerate")
        else:
            with open("/etc/systemd/system/certidude.service", "w") as fh:
                fh.write(env.get_template("server/systemd.service").render(vars()))
            click.echo("File /etc/systemd/system/certidude.service created")
    else:
        click.echo("Not systemd based OS, don't know how to set up initscripts")

    _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
    os.setgid(gid)

    if not os.path.exists(const.CONFIG_DIR):
        click.echo("Creating %s" % const.CONFIG_DIR)
        os.makedirs(const.CONFIG_DIR)

    if os.path.exists(const.CONFIG_PATH):
        click.echo("Configuration file %s already exists, remove to regenerate" % const.CONFIG_PATH)
    else:
        os.umask(0o137)
        push_token = "".join([random.choice(string.ascii_letters + string.digits) for j in range(0,32)])
        with open(const.CONFIG_PATH, "w") as fh:
            fh.write(env.get_template("server/server.conf").render(vars()))
        click.echo("Generated %s" % const.CONFIG_PATH)

    if os.path.lexists(directory):
        click.echo("CA directory %s already exists, remove to regenerate" % directory)
    else:
        click.echo("CA configuration files are saved to: {}".format(directory))

        click.echo("Generating %d-bit RSA key..." % const.KEY_SIZE)

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=const.KEY_SIZE,
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
            ).serial_number(
                random.randint(
                    0x100000000000000000000000000000000000000,
                    0xfffffffffffffffffffffffffffffffffffffff)
            ).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True,
            ).add_extension(x509.KeyUsage(
                digital_signature=server_flags,
                key_encipherment=server_flags,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False), critical=True,
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

        # Create directories with 770 permissions
        os.umask(0o027)
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Create subdirectories with 770 permissions
        os.umask(0o007)
        for subdir in ("signed", "requests", "revoked", "expired", "meta"):
            if not os.path.exists(os.path.join(directory, subdir)):
                os.mkdir(os.path.join(directory, subdir))

        # Create SQLite database file with correct permissions
        os.umask(0o117)
        with open(os.path.join(directory, "meta", "db.sqlite"), "wb") as fh:
            pass

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

    click.echo("To enable e-mail notifications install Postfix as sattelite system and set mailer address in %s" % const.CONFIG_PATH)
    click.echo()
    click.echo("Use following commands to inspect the newly created files:")
    click.echo()
    click.echo("  openssl x509 -text -noout -in %s | less" % ca_crt)
    click.echo("  openssl rsa -check -in %s" % ca_key)
    click.echo("  openssl verify -CAfile %s %s" % (ca_crt, ca_crt))
    click.echo()
    click.echo("To enable and start the service:")
    click.echo()
    click.echo("  systemctl enable certidude")
    click.echo("  systemctl start certidude")


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
    from humanize import naturaltime
    from certidude import authority

    def dump_common(common_name, path, cert):
        click.echo("certidude revoke %s" % common_name)
        with open(path, "rb") as fh:
            buf = fh.read()
            click.echo("md5sum: %s" % hashlib.md5(buf).hexdigest())
            click.echo("sha1sum: %s" % hashlib.sha1(buf).hexdigest())
            click.echo("sha256sum: %s" % hashlib.sha256(buf).hexdigest())
        click.echo()
        for ext in cert.extensions:
            print " -", ext.value
        click.echo()

    if not hide_requests:
        for common_name, path, buf, csr, server in authority.list_requests():
            created = 0
            if not verbose:
                click.echo("s " + path)
                continue
            click.echo(click.style(common_name, fg="blue"))
            click.echo("=" * len(common_name))
            click.echo("State: ? " + click.style("submitted", fg="yellow") + " " + naturaltime(created) + click.style(", %s" %created,  fg="white"))
            click.echo("openssl req -in %s -text -noout" % path)
            dump_common(common_name, path, csr)


    if show_signed:
        for common_name, path, buf, cert, server in authority.list_signed():
            if not verbose:
                if cert.not_valid_before < NOW and cert.not_valid_after > NOW:
                    click.echo("v " + path)
                elif NOW > cert.not_valid_after:
                    click.echo("e " + path)
                else:
                    click.echo("y " + path)
                continue

            click.echo(click.style(common_name, fg="blue") + " " + click.style("%x" % cert.serial, fg="white"))
            click.echo("="*(len(common_name)+60))
            expires = 0 # TODO
            if cert.not_valid_before < NOW and cert.not_valid_after > NOW:
                click.echo("Status: " + click.style("valid", fg="green") + " until " + naturaltime(cert.not_valid_after) + click.style(", %s" % cert.not_valid_after,  fg="white"))
            elif NOW > cert.not_valid_after:
                click.echo("Status: " + click.style("expired", fg="red") + " " + naturaltime(expires) + click.style(", %s" %expires,  fg="white"))
            else:
                click.echo("Status: " + click.style("not valid yet", fg="red") + click.style(", %s" %expires,  fg="white"))
            click.echo()
            click.echo("openssl x509 -in %s -text -noout" % path)
            dump_common(common_name, path, cert)

    if show_revoked:
        for common_name, path, buf, cert, server in authority.list_revoked():
            if not verbose:
                click.echo("r " + path)
                continue

            click.echo(click.style(common_name, fg="blue") + " " + click.style("%x" % cert.serial, fg="white"))
            click.echo("="*(len(common_name)+60))

            _, _, _, _, _, _, _, _, mtime, _ = os.stat(path)
            changed = datetime.fromtimestamp(mtime)
            click.echo("Status: " + click.style("revoked", fg="red") + " %s%s" % (naturaltime(NOW-changed), click.style(", %s" % changed, fg="white")))
            click.echo("openssl x509 -in %s -text -noout" % path)
            dump_common(common_name, path, cert)

    click.echo()


@click.command("sign", help="Sign certificate")
@click.argument("common_name")
@click.option("--overwrite", "-o", default=False, is_flag=True, help="Revoke valid certificate with same CN")
def certidude_sign(common_name, overwrite):
    drop_privileges()
    from certidude import authority
    cert = authority.sign(common_name, overwrite)


@click.command("revoke", help="Revoke certificate")
@click.argument("common_name")
def certidude_revoke(common_name):
    drop_privileges()
    from certidude import authority
    authority.revoke(common_name)


@click.command("cron", help="Run from cron to manage Certidude server")
def certidude_cron():
    import itertools
    from certidude import authority, config
    now = datetime.now()
    for cn, path, buf, cert, server in itertools.chain(authority.list_signed(), authority.list_revoked()):
        if cert.not_valid_after < now:
            expired_path = os.path.join(config.EXPIRED_DIR, "%x.pem" % cert.serial)
            assert not os.path.exists(expired_path)
            os.rename(path, expired_path)
            click.echo("Moved %s to %s" % (path, expired_path))


@click.command("serve", help="Run server")
@click.option("-e", "--exit-handler", default=False, is_flag=True, help="Install /api/exit/ handler")
@click.option("-p", "--port", default=80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
def certidude_serve(port, listen, fork, exit_handler):
    import pwd
    from setproctitle import setproctitle
    from certidude.signer import SignServer
    from certidude import authority, const
    click.echo("Using configuration from: %s" % const.CONFIG_PATH)


    log_handlers = []

    from certidude import config

    # Process directories
    if not os.path.exists(const.RUN_DIR):
        click.echo("Creating: %s" % const.RUN_DIR)
        os.makedirs(const.RUN_DIR)
        os.chmod(const.RUN_DIR, 0755)

    # TODO: umask!


    from logging.handlers import RotatingFileHandler
    rh = RotatingFileHandler("/var/log/certidude.log", maxBytes=1048576*5, backupCount=5)
    rh.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    log_handlers.append(rh)


    """
    Spawn signer process
    """

    if os.path.exists(const.SIGNER_SOCKET_PATH):
        os.unlink(const.SIGNER_SOCKET_PATH)

    if not os.fork():
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
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
        os.chown(const.SIGNER_SOCKET_PATH, uid, gid)
        os.chmod(const.SIGNER_SOCKET_PATH, 0770)

        click.echo("Dropping privileges of signer")
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("nobody")
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

        try:
            asyncore.loop()
        except asyncore.ExitNow:
            pass
        click.echo("Signer was shut down")
        return
    click.echo("Waiting for signer to start up")
    time_left = 2.0
    delay = 0.1
    while not os.path.exists(const.SIGNER_SOCKET_PATH) and time_left > 0:
        sleep(delay)
        time_left -= delay
    assert authority.signer_exec("ping") == "pong"
    click.echo("Signer alive")

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
    from certidude.api import certidude_app


    click.echo("Listening on %s:%d" % (listen, port))

    app = certidude_app(log_handlers)
    httpd = make_server(listen, port, app, WSGIServer)


    """
    Drop privileges
    """


    # Initialize LDAP service ticket
    if os.path.exists("/etc/cron.hourly/certidude"):
        os.system("/etc/cron.hourly/certidude")

    from certidude.push import EventSourceLogHandler
    log_handlers.append(EventSourceLogHandler())

    for j in logging.Logger.manager.loggerDict.values():
        if isinstance(j, logging.Logger): # PlaceHolder is what?
            if j.name.startswith("certidude."):
                j.setLevel(logging.DEBUG)
                for handler in log_handlers:
                    j.addHandler(handler)


    if not fork or not os.fork():
        pid = os.getpid()
        with open(const.SERVER_PID_PATH, "w") as pidfile:
            pidfile.write("%d\n" % pid)

        def exit_handler():
            logger.debug("Shutting down Certidude")
        import atexit
        atexit.register(exit_handler)
        logger.debug("Started Certidude at %s", const.FQDN)

        drop_privileges()

        class ExitResource():
            """
            Provide way to gracefully shutdown server
            """
            def on_get(self, req, resp):
                assert httpd._BaseServer__shutdown_request == False
                httpd._BaseServer__shutdown_request = True

        if exit_handler:
            app.add_route("/api/exit/", ExitResource())
        httpd.serve_forever()

        # Shut down signer as well
        assert authority.signer_exec("exit") == "ok"



@click.command("yubikey", help="Set up Yubikey as client authentication token")
@click.argument("authority")
@click.option("-p", "--pin", default="123456", help="Slot pincode, 123456 by default")
@click.option("-s", "--slot", default="9a", help="Yubikey slot to use, 9a by default")
@click.option("-u", "--username", default=os.getenv("USER"), help="Username to use, %s by default" % os.getenv("USER"))
def certidude_setup_yubikey(authority, slot, username, pin):
    import requests
    cmd = "ykinfo", "-q", "-s"
    click.echo("Executing: %s" % " ".join(cmd))
    serial = subprocess.check_output(cmd).strip()

    dn = "/CN=%s@yk-%s-%s" % (username, slot, serial)

    cmd = "yubico-piv-tool", "-a", "generate", "-s", slot, "-o", "/tmp/pk.pem"
    click.echo("Executing: %s" % " ".join(cmd))
    subprocess.call(cmd)

    cmd = "yubico-piv-tool", \
        "-i", "/tmp/pk.pem", "-o", "/tmp/req.pem", \
        "-P", pin, \
        "-S", dn, \
        "-a", "verify", "-a", "request", \
        "-s", slot
    click.echo("Executing: %s" % " ".join(cmd))

    scheme = "http"
    request_url = "%s://%s/api/request/?wait=true" % (scheme, authority)

    subprocess.check_output(cmd)
    click.echo("Submitting to %s, waiting for response..." % request_url)
    headers={
        "Content-Type": "application/pkcs10",
        "Accept": "application/x-x509-user-cert,application/x-pem-file"
    }

    submission = requests.post(request_url, data=open("/tmp/req.pem"), headers=headers)
    with open("/tmp/cert.pem", "w") as fh:
        fh.write(submission.text)

    cmd = "yubico-piv-tool", "-a", "import-certificate", "-s", slot, "-i", "/tmp/cert.pem"
    click.echo("Executing: %s" % " ".join(cmd))
    subprocess.call(cmd)


@click.command("test", help="Test mailer")
@click.argument("recipient")
def certidude_test(recipient):
    from certidude import mailer
    mailer.send(
        "test.md",
        to=recipient
    )


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
certidude_setup_openvpn.add_command(certidude_setup_openvpn_networkmanager)
certidude_setup.add_command(certidude_setup_authority)
certidude_setup.add_command(certidude_setup_openvpn)
certidude_setup.add_command(certidude_setup_strongswan)
certidude_setup.add_command(certidude_setup_nginx)
certidude_setup.add_command(certidude_setup_yubikey)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_request)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_revoke)
entry_point.add_command(certidude_list)
entry_point.add_command(certidude_users)
entry_point.add_command(certidude_cron)
entry_point.add_command(certidude_test)

if __name__ == "__main__":
    entry_point()
