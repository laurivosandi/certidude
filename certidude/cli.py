#!/usr/bin/python3
# coding: utf-8

import sys
import pwd
import random
import socket
import click
import os
import asyncore
import time
import os
import re
import logging
import signal
import netifaces
import urllib.request
from humanize import naturaltime
from ipaddress import ip_network
from time import sleep
from datetime import datetime
from OpenSSL import crypto
from setproctitle import setproctitle
from certidude.signer import SignServer
from jinja2 import Environment, PackageLoader
from certidude.wrappers import CertificateAuthorityConfig, \
    CertificateAuthority, Certificate, subject2dn, Request

env = Environment(loader=PackageLoader("certidude", "templates"))

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

config = CertificateAuthorityConfig("/etc/ssl/openssl.cnf")

# Parse command-line argument defaults from environment
HOSTNAME = socket.gethostname()
USERNAME = os.environ.get("USER")
EMAIL = USERNAME + "@" + HOSTNAME
NOW = datetime.utcnow().replace(tzinfo=None)

FIRST_NAME = None
SURNAME = None

if os.getuid() >= 1000:
    _, _, _, _, gecos, _, _ = pwd.getpwnam(USERNAME)
    if " " in gecos:
        FIRST_NAME, SURNAME = gecos.split(" ", 1)
    else:
        FIRST_NAME = gecos

def first_nic_address():
    """
    Return IP address of the first network interface
    """
    for interface in netifaces.interfaces():
        if interface == "lo":
            continue
        for iftype, addresses in netifaces.ifaddresses(interface).items():
            if iftype != 2:
                continue
            for address in addresses:
                return address.pop("addr")
    raise ValueError("Unable to determine IP address of first NIC")

def spawn_signers(kill, no_interaction):
    """
    Spawn processes for signers
    """

    os.umask(0o027)
    uid = os.getuid()
    assert uid == 0, "Not running as root"

    # Preload charmap encoding for byte_string() function of pyOpenSSL
    # in order to enable chrooting
    "".encode("charmap")

    # Process directories
    run_dir = "/run/certidude"
    signer_dir = os.path.join(run_dir, "signer")
    chroot_dir = os.path.join(signer_dir, "jail")

    # Prepare signer PID-s directory
    if not os.path.exists(signer_dir):
        click.echo("Creating: %s" % signer_dir)
        os.makedirs(signer_dir)

    # Prepare chroot directories
    if not os.path.exists(os.path.join(chroot_dir, "dev")):
        os.makedirs(os.path.join(chroot_dir, "dev"))
    if not os.path.exists(os.path.join(chroot_dir, "dev", "urandom")):
        # TODO: use os.mknod instead
        os.system("mknod -m 444 %s c 1 9" % os.path.join(chroot_dir, "dev", "urandom"))

    for ca in config.all_authorities():

        pidfile = "/run/certidude/signer/%s.pid" % ca.slug

        try:
            with open(pidfile) as fh:
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
            else:
                continue

        child_pid = os.fork()

        if child_pid == 0:
            with open(pidfile, "w") as fh:
                fh.write("%d\n" % os.getpid())

            setproctitle("%s spawn %s" % (sys.argv[0], ca.slug))
            logging.basicConfig(
                filename="/var/log/certidude-%s.log" % ca.slug,
                level=logging.INFO)
            socket_path = os.path.join(signer_dir, ca.slug + ".sock")
            click.echo("Spawned certidude signer process with PID %d at %s" % (os.getpid(), socket_path))
            server = SignServer(socket_path, ca.private_key, ca.certificate.path,
                ca.lifetime, ca.basic_constraints, ca.key_usage, ca.extended_key_usage)
            asyncore.loop()

def certidude_request_certificate(url, key_path, request_path, certificate_path, authority_path, common_name, org_unit, email_address=None, given_name=None, surname=None, autosign=False, wait=False, key_usage=None, extended_key_usage=None):
    """
    Exchange CSR for certificate using Certidude HTTP API server
    """

    # Set up URL-s
    request_params = set()
    if autosign:
        request_params.add("autosign=yes")
    if wait:
        request_params.add("wait=forever")

    if not url.endswith("/"):
        url = url + "/"

    authority_url = url + "certificate"
    request_url = url + "request"

    if request_params:
        request_url = request_url + "?" + "&".join(request_params)

    if os.path.exists(authority_path):
        click.echo("Found CA certificate in: %s" % authority_path)
    else:
        if authority_url:
            click.echo("Attempting to fetch CA certificate from %s" % authority_url)
            try:
                with urllib.request.urlopen(authority_url) as fh:
                    buf = fh.read()
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
                    except crypto.Error:
                        raise ValueError("Failed to parse PEM: %s" % buf)
                    with open(authority_path + ".part", "wb") as oh:
                        oh.write(buf)
                    click.echo("Writing CA certificate to: %s" % authority_path)
                    os.rename(authority_path + ".part", authority_path)
            except urllib.error.HTTPError as e:
                click.echo("Failed to fetch CA certificate, server responded with: %d %s" % (e.code, e.reason), err=True)
                return 1
        else:
            raise FileNotFoundError("CA certificate not found and no URL specified")

    try:
        certificate = Certificate(open(certificate_path))
        click.echo("Found certificate: %s" % certificate_path)
    except FileNotFoundError:
        try:
            request = Request(open(request_path))
            click.echo("Found signing request: %s" % request_path)
        except FileNotFoundError:

            # Construct private key
            click.echo("Generating 4096-bit RSA key...")
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 4096)

            # Dump private key
            os.umask(0o077)
            with open(key_path + ".part", "wb") as fh:
                fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

            # Construct CSR
            csr = crypto.X509Req()
            csr.set_pubkey(key)
            request = Request(csr)

            # Set subject attributes
            request.common_name = common_name
            if given_name:
                request.given_name = given_name
            if surname:
                request.surname = surname
            if org_unit:
                request.organizational_unit = org_unit

            # Set extensions
            extensions = []
            if key_usage:
                extensions.append(("keyUsage", key_usage, True))
            if extended_key_usage:
                extensions.append(("extendedKeyUsage", extended_key_usage, True))
            if email_address:
                extensions.append(("subjectAltName", "email:" + email_address, False))
            request.set_extensions(extensions)

            # Dump CSR
            os.umask(0o022)
            with open(request_path + ".part", "w") as fh:
                fh.write(request.dump())

            click.echo("Writing private key to: %s" % key_path)
            os.rename(key_path + ".part", key_path)
            click.echo("Writing certificate signing request to: %s" % request_path)
            os.rename(request_path + ".part", request_path)


        with open(request_path, "rb") as fh:
            buf = fh.read()
            submission = urllib.request.Request(request_url, buf)
            submission.add_header("User-Agent", "Certidude")
            submission.add_header("Content-Type", "application/pkcs10")

            click.echo("Submitting to %s, waiting for response..." % request_url)
            try:
                response = urllib.request.urlopen(submission)
                buf = response.read()
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
            except crypto.Error:
                raise ValueError("Failed to parse PEM: %s" % buf)
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    click.echo("Different signing request with same CN is already present on server, server refuses to overwrite", err=True)
                    return 2
                else:
                    click.echo("Failed to fetch certificate, server responded with: %d %s" % (e.code, e.reason), err=True)
                    return 3
            else:
                if response.code == 202:
                    click.echo("Server stored the request for processing (202 Accepted), but waiting was not requested, hence quitting for now", err=True)
                    return 254

            os.umask(0o022)
            with open(certificate_path + ".part", "wb") as gh:
                gh.write(buf)

            click.echo("Writing certificate to: %s" % certificate_path)
            os.rename(certificate_path + ".part", certificate_path)

    # TODO: Validate fetched certificate against CA
    # TODO: Check that recevied certificate CN and pubkey match
    # TODO: Check file permissions


@click.command("spawn", help="Run privilege isolated signer processes")
@click.option("-k", "--kill", default=False, is_flag=True, help="Kill previous instances")
@click.option("-n", "--no-interaction", default=True, is_flag=True, help="Don't load password protected keys")
def certidude_spawn(**args):
    spawn_signers(**args)


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
@click.option("--local", "-l", default=first_nic_address(), help="OpenVPN listening address, %s" % first_nic_address())
@click.option("--port", "-p", default=1194, type=click.IntRange(1,60000), help="OpenVPN listening port, 1194 by default")
@click.option('--proto', "-t", default="udp", type=click.Choice(['udp', 'tcp']), help="OpenVPN transport protocol, UDP by default")
@click.option("--config", "-o",
    default="/etc/openvpn/site-to-client.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="OpenVPN configuration file")
@click.option("--directory", "-d", default="/etc/openvpn/keys", help="Directory for keys, /etc/openvpn/keys by default")
@click.option("--key-path", "-k", default=HOSTNAME + ".key", help="Key path, %s.key relative to --directory by default" % HOSTNAME)
@click.option("--request-path", "-r", default=HOSTNAME + ".csr", help="Request path, %s.csr relative to --directory by default" % HOSTNAME)
@click.option("--certificate-path", "-c", default=HOSTNAME + ".crt", help="Certificate path, %s.crt relative to --directory by default" % HOSTNAME)
@click.option("--authority-path", "-a", default="ca.crt", help="Certificate authority certificate path, ca.crt relative to --dir by default")
def certidude_setup_openvpn_server(url, config, subnet, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, local, proto, port):
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

    if directory:
        if not os.path.exists(directory):
            click.echo("Making directory: %s" % directory)
            os.makedirs(directory)
        key_path = os.path.join(directory, key_path)
        certificate_path = os.path.join(directory, certificate_path)
        request_path = os.path.join(directory, request_path)
        authority_path = os.path.join(directory, authority_path)

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
        extended_key_usage="serverAuth",
        wait=True)

    if retval:
        return retval

    # TODO: Add dhparam
    config.write(env.get_template("site-to-client.ovpn").render(locals()))

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
def certidude_setup_openvpn_client(url, config, email_address, common_name, org_unit, directory, key_path, request_path, certificate_path, authority_path, proto, remote):

    if directory:
        if not os.path.exists(directory):
            click.echo("Making directory: %s" % directory)
            os.makedirs(directory)
        key_path = os.path.join(directory, key_path)
        certificate_path = os.path.join(directory, certificate_path)
        request_path = os.path.join(directory, request_path)
        authority_path = os.path.join(directory, authority_path)

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
    config.write(env.get_template("client-to-site.ovpn").render(locals()))

    click.echo("Generated %s" % config.name)
    click.echo()
    click.echo("Inspect newly created %s and start OpenVPN service:" % config.name)
    click.echo()
    click.echo("  service openvpn restart")
    click.echo()


@click.command("authority", help="Set up Certificate Authority in a directory")
@click.option("--group", "-g", default="certidude", help="Group for file permissions, certidude by default")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=HOSTNAME, help="Common name, hostname by default")
@click.option("--country", "-c", default="ee", help="Country, Estonia by default")
@click.option("--state", "-s", default="Harjumaa", help="State or country, Harjumaa by default")
@click.option("--locality", "-l", default="Tallinn", help="City or locality, Tallinn by default")
@click.option("--lifetime", default=20*365, help="Lifetime in days, 7300 days (20 years) by default")
@click.option("--organization", "-o", default="Example LLC", help="Company or organization name")
@click.option("--organizational-unit", "-ou", default="Certification Department")
@click.option("--crl-age", default=1, help="CRL expiration age, 1 day by default")
@click.option("--pkcs11", default=False, is_flag=True, help="Use PKCS#11 token instead of files")
@click.option("--crl-distribution-url", default=None, help="CRL distribution URL")
@click.option("--ocsp-responder-url", default=None, help="OCSP responder URL")
@click.option("--email-address", default=EMAIL, help="CA e-mail address")
@click.option("--inbox", default="imap://user:pass@host:port/INBOX", help="Inbound e-mail server")
@click.option("--outbox", default="smtp://localhost", help="Outbound e-mail server")
@click.argument("directory")
def certidude_setup_authority(parent, country, state, locality, organization, organizational_unit, common_name, directory, crl_age, lifetime, pkcs11, group, crl_distribution_url, ocsp_responder_url, email_address, inbox, outbox):
    logging.info("Creating certificate authority in %s", directory)
    _, _, uid, gid, gecos, root, shell = pwd.getpwnam(group)
    os.setgid(gid)

    click.echo("Generating 4096-bit RSA key...")

    if pkcs11:
        raise NotImplementedError("Hardware token support not yet implemented!")
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

    slug = os.path.basename(directory)

    if not crl_distribution_url:
        crl_distribution_url = "http://%s/api/%s/revoked/" % (common_name, slug)

    # File paths
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_crt = os.path.join(directory, "ca_crt.pem")
    ca_crl = os.path.join(directory, "ca_crl.pem")
    crl_distribution_points = "URI:%s" % crl_distribution_url

    ca = crypto.X509()
    #ca.set_version(3) # breaks gcr-viewer?!
    ca.set_serial_number(1)
    ca.get_subject().CN = common_name
    ca.get_subject().C = country
    ca.get_subject().ST = state
    ca.get_subject().L = locality
    ca.get_subject().O = organization
    ca.get_subject().OU = organizational_unit
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(lifetime * 24 * 60 * 60)
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

    if not ocsp_responder_url:
        ocsp_responder_url = "http://%s/api/%s/ocsp/" % (common_name, slug)
        authority_info_access = "OCSP;URI:%s" % ocsp_responder_url
        ca.add_extensions([
            crypto.X509Extension(
                b"authorityInfoAccess",
                False,
                authority_info_access.encode("ascii"))
        ])

    click.echo("Signing %s..." % subject2dn(ca.get_subject()))

    # openssl x509 -in ca_crt.pem -outform DER | sha1sum
    # openssl x509 -fingerprint -in ca_crt.pem

    ca.sign(key, "sha1")

    os.umask(0o027)
    if not os.path.exists(directory):
        os.makedirs(directory)

    os.umask(0o007)

    for subdir in ("signed", "requests", "revoked"):
        if not os.path.exists(os.path.join(directory, subdir)):
            os.mkdir(os.path.join(directory, subdir))
    with open(ca_crl, "wb") as fh:
        crl = crypto.CRL()
        fh.write(crl.export(ca, key, days=crl_age))
    with open(os.path.join(directory, "serial"), "w") as fh:
        fh.write("1")

    os.umask(0o027)
    with open(ca_crt, "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))


    os.umask(0o077)
    with open(ca_key, "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    click.echo("Insert following to /etc/ssl/openssl.cnf:")
    click.echo()
    click.secho(env.get_template("openssl.cnf").render(locals()), fg="blue")

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
@click.option("--show-key-type", "-k", default=False, is_flag=True, help="Show key type and length")
@click.option("--show-path", "-p", default=False, is_flag=True, help="Show filesystem paths")
@click.option("--show-extensions", "-e", default=False, is_flag=True, help="Show X.509 Certificate Extensions")
def certidude_list(ca, show_key_type, show_extensions, show_path):
    from pycountry import countries
    def dump_common(j):
        if show_path:
            click.echo(" |    |   Path: %s" % j.path)

        person = [j for j in (j.given_name, j.surname) if j]
        if person:
            click.echo(" |    |   Associated person: %s" % " ".join(person) + (" <%s>" % j.email_address if j.email_address else ""))
        elif j.email_address:
            click.echo(" |    |   Associated e-mail: " + j.email_address)

        bits = [j for j in (
            countries.get(alpha2=j.country_code.upper()).name if
            j.country_code else "",
            j.state_or_county,
            j.city,
            j.organization,
            j.organizational_unit) if j]
        if bits:
            click.echo(" |    |   Organization: %s" % ", ".join(bits))

        if show_key_type:
            click.echo(" |    |   Key type: %s-bit %s" % (j.key_length, j.key_type))

        if show_extensions:
            for key, value, data in j.extensions:
                click.echo((" |    |   Extension " + key + ":").ljust(50) + " " + value)
        elif j.key_usage:
            click.echo(" |    |   Key usage: " + j.key_usage)
        click.echo(" |    |")

    for ca in config.all_authorities():
        click.echo("Certificate authority " + click.style(ca.slug, fg="blue"))
#        if ca.certificate.email_address:
#            click.echo("  \u2709 %s" % ca.certificate.email_address)

        if ca.certificate.signed < NOW and ca.certificate.expires > NOW:
            print(ca.certificate.expires)
            click.echo(" | \u2713 Certificate: " + click.style("valid", fg="green") + ", %s" % ca.certificate.expires)
        elif NOW > ca.certificate.expires:
            click.echo(" | \u2717 Certificate: " + click.style("expired", fg="red"))
        else:
            click.echo(" | \u2717 Certificate: " + click.style("not valid yet", fg="red"))

        if os.path.exists(ca.private_key):
            click.echo(" | \u2713 Private key " + ca.private_key + ": " + click.style("okay", fg="green"))
            # TODO: Check permissions
        else:
            click.echo(" | \u2717 Private key " + ca.private_key + ": " + click.style("does not exist", fg="red"))

        if os.path.isdir(ca.signed_dir):
            click.echo(" | \u2713 Signed certificates directory " + ca.signed_dir + ": " + click.style("okay", fg="green"))
        else:
            click.echo(" | \u2717 Signed certificates directory " + ca.signed_dir + ": " + click.style("does not exist", fg="red"))

        if ca.revoked_dir:
            click.echo(" |   Revoked certificates directory: %s" % ca.revoked_dir)

        click.echo(" +-- Pending requests")

        for j in ca.get_requests():
            click.echo(" |    +-- Request " + click.style(j.common_name, fg="blue"))
            click.echo(" |    |   Submitted: %s, %s" % (naturaltime(j.created), j.created))
            dump_common(j)

        click.echo(" +-- Signed certificates")

        for j in ca.get_signed():
            click.echo(" |    +-- Certificate " + click.style(j.common_name, fg="blue") + " " + click.style(":".join(re.findall("\d\d", j.serial_number)), fg="white"))

            if j.signed < NOW and j.expires > NOW:
                click.echo(" |    | \u2713 Certificate " + click.style("valid", fg="green") + " " + naturaltime(j.expires))
            elif NOW > j.expires:
                click.echo(" |    | \u2717 Certificate " + click.style("expired", fg="red") + " " + naturaltime(j.expires))
            else:
                click.echo(" |    | \u2717 Certificate " + click.style("not valid yet", fg="red"))
            dump_common(j)

        click.echo(" +-- Revocations")

        for j in ca.get_revoked():
            click.echo(" |    +-- Revocation " + click.style(j.common_name, fg="blue") + " " + click.style(":".join(re.findall("\d\d", j.serial_number)), fg="white"))
     #       click.echo(" |    |   Serial: %s" % ":".join(re.findall("\d\d", j.serial_number)))
            if show_path:
                click.echo(" |    |   Path: %s" % j.path)
            click.echo(" |    |   Revoked: %s%s" % (naturaltime(NOW-j.changed), click.style(", %s" % j.changed, fg="white")))
            dump_common(j)

        click.echo()

@click.command("list", help="List Certificate Authorities")
@click.argument("ca")
@config.pop_certificate_authority()
def cert_list(ca):

    mapping = {}

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
        os.unlink(request.path)
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
    spawn_signers(kill=False, no_interaction=False)

    logging.basicConfig(
        filename='/var/log/certidude.log',
        level=logging.DEBUG)

    click.echo("Serving API at %s:%d" % (listen, port))
    import pwd
    import falcon
    from wsgiref.simple_server import make_server, WSGIServer
    from socketserver import ThreadingMixIn
    from certidude.api import CertificateAuthorityResource, \
        RequestDetailResource, RequestListResource, \
        SignedCertificateDetailResource, SignedCertificateListResource, \
        RevocationListResource, IndexResource, ApplicationConfigurationResource, \
        CertificateStatusResource

    class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
        pass

    click.echo("Listening on %s:%d" % (listen, port))

    app = falcon.API()
    app.add_route("/api/{ca}/ocsp/", CertificateStatusResource(config))
    app.add_route("/api/{ca}/signed/{cn}/openvpn", ApplicationConfigurationResource(config))
    app.add_route("/api/{ca}/certificate/", CertificateAuthorityResource(config))
    app.add_route("/api/{ca}/revoked/", RevocationListResource(config))
    app.add_route("/api/{ca}/signed/{cn}/", SignedCertificateDetailResource(config))
    app.add_route("/api/{ca}/signed/", SignedCertificateListResource(config))
    app.add_route("/api/{ca}/request/{cn}/", RequestDetailResource(config))
    app.add_route("/api/{ca}/request/", RequestListResource(config))
    app.add_route("/api/{ca}/", IndexResource(config))
    httpd = make_server(listen, port, app, ThreadingWSGIServer)
    if user:
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam(user)
        if uid == 0:
            click.echo("Please specify unprivileged user")
            exit(254)
        click.echo("Switching to user %s (uid=%d, gid=%d)" % (user, uid, gid))
        os.setgid(gid)
        os.setuid(uid)
        os.umask(0o007)
    elif os.getuid() == 0:
        click.echo("Warning: running as root, this is not reccommended!")
    httpd.serve_forever()

@click.group("openvpn", help="OpenVPN helpers")
def certidude_setup_openvpn(): pass

@click.group("setup", help="Getting started section")
def certidude_setup(): pass

@click.group()
def entry_point(): pass

certidude_setup_openvpn.add_command(certidude_setup_openvpn_server)
certidude_setup_openvpn.add_command(certidude_setup_openvpn_client)
certidude_setup.add_command(certidude_setup_authority)
certidude_setup.add_command(certidude_setup_openvpn)
certidude_setup.add_command(certidude_setup_client)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_spawn)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_list)
