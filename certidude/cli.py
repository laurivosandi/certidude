# coding: utf-8

import click
import hashlib
import logging
import os
import random
import re
import signal
import string
import subprocess
import sys
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from asn1crypto.crl import CertificateList
from base64 import b64encode
from certbuilder import CertificateBuilder, pem_armor_certificate
from certidude import const
from csrbuilder import CSRBuilder, pem_armor_csr
from configparser import ConfigParser, NoOptionError
from certidude.common import apt, rpm, drop_privileges, selinux_fixup, cn_to_dn, generate_serial
from datetime import datetime, timedelta
from glob import glob
from ipaddress import ip_network
from oscrypto import asymmetric

try:
    import coverage
    cov = coverage.process_startup()
    if cov:
        click.echo("Enabling coverage tracking")
    else:
        click.echo("Coverage tracking not requested")
except ImportError:
    pass

logger = logging.getLogger(__name__)

# http://www.mad-hacking.net/documentation/linux/security/ssl-tls/creating-ca.xml
# https://kjur.github.io/jsrsasign/
# keyUsage, extendedKeyUsage - https://www.openssl.org/docs/apps/x509v3_client_config.html
# strongSwan key paths - https://wiki.strongswan.org/projects/1/wiki/SimpleCA

NOW = datetime.utcnow()

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
            common_name = arguments.get("common_name")
            authority = arguments.get("authority")
            b = os.path.join("/etc/certidude/authority", authority)
            if dh:
                path = os.path.join("/etc/ssl/dhparam.pem")
                if not os.path.exists(path):
                    rpm("openssl")
                    apt("openssl")
                    cmd = "openssl", "dhparam", "-out", path, str(const.KEY_SIZE)
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
                with open(const.CLIENT_CONFIG_PATH + ".part", 'w') as fh:
                    client_config.write(fh)
                os.rename(const.CLIENT_CONFIG_PATH + ".part", const.CLIENT_CONFIG_PATH)
                click.echo("Section '%s' added to %s" % (authority, const.CLIENT_CONFIG_PATH))

            for j in ("key", "request", "certificate", "authority", "revocations"):
                arguments["%s_path" % j] = client_config.get(authority, "%s path" % j)

            return func(**arguments)
        return wrapped
    return wrapper


class ConfigTreeParser(ConfigParser):
    def __init__(self, path, *args, **kwargs):
        ConfigParser.__init__(self, *args, **kwargs)
        if os.path.exists(path):
            with open(path) as fh:
                click.echo("Parsing: %s" % fh.name)
                self.readfp(fh)
        if os.path.exists(path + ".d"):
            for filename in os.listdir(path + ".d"):
                if not filename.endswith(".conf"):
                    continue
                with open(os.path.join(path + ".d", filename)) as fh:
                    click.echo("Parsing: %s" % fh.name)
                    self.readfp(fh)


@click.command("enroll", help="Run processes for requesting certificates and configuring services")
@click.option("-k", "--kerberos", default=False, is_flag=True, help="Offer system keytab for auth")
@click.option("-r", "--renew", default=False, is_flag=True, help="Renew now")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
@click.option("-s", "--skip-self", default=False, is_flag=True, help="Skip self enroll")
@click.option("-nw", "--no-wait", default=False, is_flag=True, help="Return immideately if server doesn't autosign")
def certidude_enroll(fork, renew, no_wait, kerberos, skip_self):
    assert os.getuid() == 0 and os.getgid() == 0, "Can enroll only as root"

    if not skip_self and os.path.exists(const.SERVER_CONFIG_PATH):
        click.echo("Self-enrolling authority's web interface certificate")
        from certidude import authority
        authority.self_enroll()

    from jinja2 import Environment, PackageLoader
    context = globals()
    context.update(locals())
    env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)
    if not os.path.exists("/etc/systemd/system/certidude-enroll.timer"):
        click.echo("Creating systemd timer...")
        with open("/etc/systemd/system/certidude-enroll.timer", "w") as fh:
            fh.write(env.get_template("client/certidude.timer").render(context))
    if not os.path.exists("/etc/systemd/system/certidude-enroll.service"):
        click.echo("Creating systemd service...")
        with open("/etc/systemd/system/certidude-enroll.service", "w") as fh:
            fh.write(env.get_template("client/certidude.service").render(context))
    os.system("systemctl daemon-reload")
    os.system("systemctl enable certidude-enroll.timer")
    os.system("systemctl start certidude-enroll.timer")

    if not os.path.exists(const.CLIENT_CONFIG_PATH):
        click.echo("Client not configured, so not going to enroll")
        return

    import requests

    clients = ConfigTreeParser(const.CLIENT_CONFIG_PATH)
    service_config = ConfigTreeParser(const.SERVICES_CONFIG_PATH)

    # Process directories
    if not os.path.exists(const.RUN_DIR):
        click.echo("Creating: %s" % const.RUN_DIR)
        os.makedirs(const.RUN_DIR)

    for authority_name in clients.sections():
        # TODO: Create directories automatically

        try:
            trigger = clients.get(authority_name, "trigger")
        except NoOptionError:
            trigger = "interface up"

        if trigger == "domain joined":
            # Stop further processing if command line argument said so or trigger expects domain membership
            if not os.path.exists("/etc/krb5.keytab"):
                continue
            kerberos = True
        elif trigger == "interface up":
            pass
        else:
            raise


        #########################
        ### Fork if requested ###
        #########################

        pid_path = os.path.join(const.RUN_DIR, authority_name + ".pid")

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

        try:
            authority_path = clients.get(authority_name, "authority path")
        except NoOptionError:
            authority_path = "/etc/certidude/authority/%s/ca_cert.pem" % authority_name
        finally:
            if os.path.exists(authority_path):
                click.echo("Found authority certificate in: %s" % authority_path)
                with open(authority_path, "rb") as fh:
                    header, _, certificate_der_bytes = pem.unarmor(fh.read())
                    authority_certificate = x509.Certificate.load(certificate_der_bytes)
            else:
                if not os.path.exists(os.path.dirname(authority_path)):
                    os.makedirs(os.path.dirname(authority_path))
                authority_url = "http://%s/api/certificate/" % authority_name
                click.echo("Attempting to fetch authority certificate from %s" % authority_url)
                try:
                    r = requests.get(authority_url,
                        headers={"Accept": "application/x-x509-ca-cert,application/x-pem-file"})
                    header, _, certificate_der_bytes = pem.unarmor(r.content)
                    authority_certificate = x509.Certificate.load(certificate_der_bytes)
                except: # TODO: catch correct exceptions
                    raise
                #    raise ValueError("Failed to parse PEM: %s" % r.text)
                authority_partial = authority_path + ".part"
                with open(authority_partial, "wb") as oh:
                    oh.write(r.content)
                click.echo("Writing authority certificate to: %s" % authority_path)
                selinux_fixup(authority_partial)
                os.rename(authority_partial, authority_path)

            authority_public_key = asymmetric.load_public_key(
                authority_certificate["tbs_certificate"]["subject_public_key_info"])



        # Attempt to install CA certificates system wide
        try:
            authority_system_wide = clients.getboolean(authority_name, "system wide")
        except NoOptionError:
            authority_system_wide = False
        finally:
            if authority_system_wide:
                # Firefox, Chromium, wget, curl on Fedora
                # Note that if ~/.pki/nssdb has been customized before, curl breaks
                if os.path.exists("/usr/bin/update-ca-trust"):
                    link_path = "/etc/pki/ca-trust/source/anchors/%s" % authority_name
                    if not os.path.lexists(link_path):
                        os.symlink(authority_path, link_path)
                    os.system("update-ca-trust")

                # curl on Fedora ?
                # pip

                # Firefox (?) on Debian, Ubuntu
                if os.path.exists("/usr/bin/update-ca-certificates") or os.path.exists("/usr/sbin/update-ca-certificates"):
                    link_path = "/usr/local/share/ca-certificates/%s" % authority_name
                    if not os.path.lexists(link_path):
                        os.symlink(authority_path, link_path)
                    os.system("update-ca-certificates")

                # TODO: test for curl, wget


        ###############
        ### Get CRL ###
        ###############

        try:
            revocations_path = clients.get(authority_name, "revocations path")
        except NoOptionError:
            revocations_path = None
        else:
            # Fetch certificate revocation list
            revoked_url = "http://%s/api/revoked/" % authority_name
            click.echo("Fetching CRL from %s to %s" % (revoked_url, revocations_path))
            r = requests.get(revoked_url, headers={'accept': 'application/x-pem-file'})

            if r.status_code == 200:
                header, _, crl_der_bytes = pem.unarmor(r.content)
                revocations = CertificateList.load(crl_der_bytes)
                # TODO: check signature, parse reasons, remove keys if revoked
                revocations_partial = revocations_path + ".part"
                with open(revocations_partial, 'wb') as f:
                    f.write(r.content)
                os.rename(revocations_partial, revocations_path)
            elif r.status_code == 404:
                click.echo("CRL disabled, server said 404")
            else:
                click.echo("Failed to fetch CRL from %s, got %s" % (revoked_url, r.text))


        try:
            common_name = clients.get(authority_name, "common name")
        except NoOptionError:
            click.echo("No common name specified for %s, not requesting a certificate" % authority_name)
            continue

        # If deriving common name from *current* hostname is preferred
        if common_name == "$HOSTNAME":
            common_name = const.HOSTNAME
        elif common_name == "$FQDN":
            common_name = const.FQDN
        elif "$" in common_name:
            raise ValueError("Invalid variable '%s' supplied, only $HOSTNAME and $FQDN allowed" % common_name)
        if not re.match(const.RE_COMMON_NAME, common_name):
            raise ValueError("Supplied common name %s doesn't match the expression %s" % (common_name, const.RE_COMMON_NAME))


        ################################
        ### Generate keypair and CSR ###
        ################################

        try:
            key_path = clients.get(authority_name, "key path")
            request_path = clients.get(authority_name, "request path")
        except NoOptionError:
            key_path = "/etc/certidude/authority/%s/host_key.pem" % authority_name
            request_path = "/etc/certidude/authority/%s/host_csr.pem" % authority_name

        if os.path.exists(request_path):
            with open(request_path, "rb") as fh:
                header, _, der_bytes = pem.unarmor(fh.read())
                csr = CertificationRequest.load(der_bytes)
                if csr["certification_request_info"]["subject"].native["common_name"] != common_name:
                    click.echo("Stored request's common name differs from currently requested one, deleting old request")
                    os.remove(request_path)

        if not os.path.exists(request_path):
            key_partial = key_path + ".part"
            request_partial = request_path + ".part"

            if authority_public_key.algorithm == "ec":
                self_public_key, private_key = asymmetric.generate_pair("ec", curve=authority_public_key.curve)
            elif authority_public_key.algorithm == "rsa":
                self_public_key, private_key = asymmetric.generate_pair("rsa", bit_size=authority_public_key.bit_size)
            else:
                NotImplemented

            builder = CSRBuilder({"common_name": common_name}, self_public_key)
            request = builder.build(private_key)
            with open(key_partial, 'wb') as f:
                f.write(asymmetric.dump_private_key(private_key, None))
            with open(request_partial, 'wb') as f:
                f.write(pem_armor_csr(request))
            selinux_fixup(key_partial)
            selinux_fixup(request_partial)
            os.rename(key_partial, key_path)
            os.rename(request_partial, request_path)


        ##############################################
        ### Submit CSR and save signed certificate ###
        ##############################################

        try:
            certificate_path = clients.get(authority_name, "certificate path")
        except NoOptionError:
            certificate_path = "/etc/certidude/authority/%s/host_cert.pem" % authority_name

        try:
            renewal_overlap = clients.getint(authority_name, "renewal overlap")
        except NoOptionError: # Renewal not configured
            renewal_overlap = None

        try:
            with open(certificate_path, "rb") as ch, open(request_path, "rb") as rh, open(key_path, "rb") as kh:
                cert_buf = ch.read()
                cert = asymmetric.load_certificate(cert_buf)
                expires = cert.asn1["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None)
                if renewal_overlap and NOW > expires - timedelta(days=renewal_overlap):
                    click.echo("Certificate will expire %s, will attempt to renew" % expires)
                    renew = True
        except EnvironmentError: # Certificate missing, can't renew
            pass

        try:
            autosign = clients.getboolean(authority_name, "autosign")
        except NoOptionError:
            autosign = True

        if not os.path.exists(certificate_path) or renew:
            # Set up URL-s
            request_params = set()
            request_params.add("autosign=%s" % ("yes" if autosign else "no"))
            if not no_wait:
                request_params.add("wait=forever")

            kwargs = {
                "data": open(request_path),
                "verify": authority_path,
                "headers": {
                    "Content-Type": "application/pkcs10",
                    "Accept": "application/x-x509-user-cert,application/x-pem-file"
                }
            }

            if renew: # Do mutually authenticated TLS handshake
                kwargs["cert"] = certificate_path, key_path
                click.echo("Renewing using current keypair at %s %s" % kwargs["cert"])
            else:
                # If machine is joined to domain attempt to present machine credentials for authentication
                if kerberos:
                    try:
                        from requests_kerberos import HTTPKerberosAuth, OPTIONAL
                    except ImportError:
                        click.echo("Kerberos bindings not available, please install requests-kerberos")
                    else:
                        os.environ["KRB5CCNAME"]="/tmp/ca.ticket"

                        # Mac OS X has keytab with lowercase hostname
                        cmd = "kinit -S HTTP/%s -k %s$" % (authority_name, const.HOSTNAME.lower())
                        click.echo("Executing: %s" % cmd)
                        if os.system(cmd):
                            # Fedora /w SSSD has keytab with uppercase hostname
                            cmd = "kinit -S HTTP/%s -k %s$" % (authority_name, const.HOSTNAME.upper())
                            if os.system(cmd):
                                # Failed, probably /etc/krb5.keytab contains spaghetti
                                raise ValueError("Failed to initialize Kerberos service ticket using machine keytab")
                        assert os.path.exists("/tmp/ca.ticket"), "Ticket not created!"
                        click.echo("Initialized Kerberos service ticket using machine keytab")
                        kwargs["auth"] = HTTPKerberosAuth(mutual_authentication=OPTIONAL, force_preemptive=True)
                else:
                    click.echo("Not using machine keytab")

            request_url = "https://%s:8443/api/request/" % authority_name
            if request_params:
                request_url = request_url + "?" + "&".join(request_params)
            submission = requests.post(request_url, **kwargs)

            # Destroy service ticket
            if os.path.exists("/tmp/ca.ticket"):
                os.system("kdestroy")

            if submission.status_code == requests.codes.ok:
                pass
            if submission.status_code == requests.codes.accepted:
                click.echo("Server accepted the request, but refused to sign immideately (%s). Waiting was not requested, hence quitting for now" % submission.text)
                os.unlink(pid_path)
                continue
            if submission.status_code == requests.codes.conflict:
                raise errors.DuplicateCommonNameError("Different signing request with same CN is already present on server, server refuses to overwrite")
            elif submission.status_code == requests.codes.gone:
                # Should the client retry or disable request submission?
                raise ValueError("Server refused to sign the request") # TODO: Raise proper exception
            elif submission.status_code == requests.codes.bad_request:
                raise ValueError("Server said following, likely current certificate expired/revoked? %s" % submission.text)
            else:
                submission.raise_for_status()

            try:
                header, _, certificate_der_bytes = pem.unarmor(submission.content)
                cert = x509.Certificate.load(certificate_der_bytes)
            except: # TODO: catch correct exceptions
                raise ValueError("Failed to parse PEM: %s" % submission.text)

            assert cert.subject.native["common_name"] == common_name, \
                "Expected certificate with common name %s, but got %s instead" % \
                    (common_name, cert.subject.native["common_name"])

            os.umask(0o022)
            certificate_partial = certificate_path + ".part"
            with open(certificate_partial, "w") as fh:
                # Dump certificate
                fh.write(submission.text)

            click.echo("Writing certificate to: %s" % certificate_path)
            selinux_fixup(certificate_partial)
            os.rename(certificate_partial, certificate_path)

            # Nginx requires bundle
            try:
                bundle_path = clients.get(authority_name, "bundle path")
            except NoOptionError:
                pass
            else:
                bundle_partial = bundle_path + ".part"
                with open(bundle_partial, "w") as fh:
                    fh.write(submission.text)
                    with open(authority_path) as ch:
                        fh.write(ch.read())
                click.echo("Writing bundle to: %s" % bundle_path)
                os.rename(bundle_partial, bundle_path)
        else:
            click.echo("Certificate found at %s and no renewal requested" % certificate_path)


        ##################################
        ### Configure related services ###
        ##################################

        for endpoint in service_config.sections():
            if service_config.get(endpoint, "authority") != authority_name:
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
                    with open("/etc/systemd/system/openvpn-reconnect.service.part", "w") as fh:
                        fh.write(env.get_template("client/openvpn-reconnect.service").render(context))
                    os.rename("/etc/systemd/system/openvpn-reconnect.service.part",
                        "/etc/systemd/system/openvpn-reconnect.service")
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
                    if config[section_type,section_name]["leftcert"] != certificate_path:
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

                # Tune AppArmor profile, TODO: retain contents
                if os.path.exists("/etc/apparmor.d/local"):
                    with open("/etc/apparmor.d/local/usr.lib.ipsec.charon", "w") as fh:
                        fh.write(key_path + " r,\n")
                        fh.write(authority_path + " r,\n")
                        fh.write(certificate_path + " r,\n")

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
                # NetworkManager-strongswan-gnome
                nm_config_path = os.path.join("/etc/NetworkManager/system-connections", endpoint)
                if os.path.exists(nm_config_path):
                    click.echo("Not creating %s, remove to regenerate" % nm_config_path)
                    continue
                nm_config = ConfigParser()
                nm_config.add_section("connection")
                nm_config.set("connection", "certidude managed", "true")
                nm_config.set("connection", "id", endpoint)
                nm_config.set("connection", "uuid", uuid)
                nm_config.set("connection", "type", "vpn")
                nm_config.add_section("vpn")
                nm_config.set("vpn", "service-type", "org.freedesktop.NetworkManager.openvpn")
                nm_config.set("vpn", "connection-type", "tls")
                nm_config.set("vpn", "comp-lzo", "no")
                nm_config.set("vpn", "cert-pass-flags", "0")
                nm_config.set("vpn", "tap-dev", "no")
                nm_config.set("vpn", "remote-cert-tls", "server") # Assert TLS Server flag of X.509 certificate
                nm_config.set("vpn", "remote", service_config.get(endpoint, "remote"))
                nm_config.set("vpn", "key", key_path)
                nm_config.set("vpn", "cert", certificate_path)
                nm_config.set("vpn", "ca", authority_path)
                nm_config.set("vpn", "tls-cipher", "TLS-%s-WITH-AES-256-GCM-SHA384" % (
                    "ECDHE-ECDSA" if authority_public_key.algorithm == "ec" else "DHE-RSA"))
                nm_config.set("vpn", "cipher", "AES-128-GCM")
                nm_config.set("vpn", "auth", "SHA384")
                nm_config.add_section("ipv4")
                nm_config.set("ipv4", "method", "auto")
                nm_config.set("ipv4", "never-default", "true")
                nm_config.add_section("ipv6")
                nm_config.set("ipv6", "method", "auto")

                try:
                    nm_config.set("vpn", "port", str(service_config.getint(endpoint, "port")))
                except NoOptionError:
                    nm_config.set("vpn", "port", "1194")

                try:
                    if service_config.get(endpoint, "proto") == "tcp":
                        nm_config.set("vpn", "proto-tcp", "yes")
                except NoOptionError:
                    pass

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
            if service_config.get(endpoint, "service") == "network-manager/strongswan":
                client_config = ConfigParser()
                nm_config = ConfigParser()
                nm_config.add_section("connection")
                nm_config.set("connection", "certidude managed", "true")
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
                nm_config.set("vpn", "userkey", key_path)
                nm_config.set("vpn", "usercert", certificate_path)
                nm_config.set("vpn", "certificate", authority_path)
                dhgroup = "ecp384" if authority_public_key.algorithm == "ec" else "modp2048"
                nm_config.set("vpn", "ike", "aes256-sha384-prfsha384-" + dhgroup)
                nm_config.set("vpn", "esp", "aes128gcm16-aes128gmac-" + dhgroup)
                nm_config.set("vpn", "proposal", "yes")

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

        with open(const.SERVICES_CONFIG_PATH + ".part", 'w') as fh:
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
    config.write(";comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")
    config.write("#ifconfig-pool-persist /tmp/openvpn-leases.txt\n")


    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude enroll")


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
        with open(const.SERVICES_CONFIG_PATH + ".part", 'w') as fh:
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
    config.write(";comp-lzo\n")
    config.write("user nobody\n")
    config.write("group nogroup\n")
    config.write("persist-tun\n")
    config.write("persist-key\n")
    config.write("up /etc/openvpn/update-resolv-conf\n")
    config.write("down /etc/openvpn/update-resolv-conf\n")

    click.echo("Generated %s" % config.name)
    click.echo("Inspect generated files and issue following to request certificate:")
    click.echo()
    click.echo("  certidude enroll")


@click.command("server", help="Set up strongSwan server")
@click.argument("authority")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name, %s by default" % const.FQDN)
@click.option("--subnet", "-sn", default="192.168.33.0/24", type=ip_network, help="IPsec virtual subnet, 192.168.33.0/24 by default")
@click.option("--route", "-r", type=ip_network, multiple=True, help="Subnets to advertise via this connection, multiple allowed")
@fqdn_required
@setup_client(prefix="server_")
def certidude_setup_strongswan_server(authority, common_name, subnet, route, **paths):
    # Install dependencies
    apt("strongswan")
    rpm("strongswan")

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
        with open(const.SERVICES_CONFIG_PATH + ".part", 'w') as fh:
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
        with open(const.SERVICES_CONFIG_PATH + ".part", 'w') as fh:
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
    click.echo("Run 'certidude enroll' to request certificates and to enable services")


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
        with open(const.SERVICES_CONFIG_PATH + ".part", 'w') as fh:
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
@click.option("--tls-config",
    default="/etc/nginx/conf.d/tls.conf",
    type=click.File(mode="w", atomic=True, lazy=True),
    help="TLS configuration file of nginx, /etc/nginx/conf.d/tls.conf by default")
@click.option("--common-name", "-cn", default=const.FQDN, help="Common name of the server, %s by default" % const.FQDN)
@click.option("--title", "-t", default="Certidude at %s" % const.FQDN, help="Common name of the certificate authority, 'Certidude at %s' by default" % const.FQDN)
@click.option("--authority-lifetime", default=20*365, help="Authority certificate lifetime in days, 20 years by default")
@click.option("--organization", "-o", default=None, help="Company or organization name")
@click.option("--organizational-unit", "-ou", default="Certificate Authority")
@click.option("--push-server", help="Push server, by default http://%s" % const.FQDN)
@click.option("--directory", default="/var/lib/certidude", help="Directory for authority files")
@click.option("--outbox", default="smtp://smtp.%s" % const.DOMAIN, help="SMTP server, smtp://smtp.%s by default" % const.DOMAIN)
@click.option("--skip-assets", is_flag=True, help="Don't attempt to assemble JS/CSS/font assets")
@click.option("--skip-packages", is_flag=True, help="Don't attempt to install apt/pip/npm packages")
@click.option("--packages-only", is_flag=True, help="Install only apt/pip/npm packages")
@click.option("--elliptic-curve", "-e", is_flag=True, help="Generate EC instead of RSA keypair")
@click.option("--subordinate", is_flag=True, help="Set up subordinate CA instead of root CA")
def certidude_setup_authority(username, kerberos_keytab, nginx_config, tls_config, organization, organizational_unit, common_name, directory, authority_lifetime, push_server, outbox, title, skip_assets, skip_packages, elliptic_curve, subordinate, packages_only):
    assert subprocess.check_output(["/usr/bin/lsb_release", "-cs"]) in (b"trusty\n", b"xenial\n", b"bionic\n"), "Only Ubuntu 16.04 supported at the moment"
    assert os.getuid() == 0 and os.getgid() == 0, "Authority can be set up only by root"

    import pwd
    from jinja2 import Environment, PackageLoader
    env = Environment(loader=PackageLoader("certidude", "templates"), trim_blocks=True)

    if skip_packages:
        click.echo("Not attempting to install packages as requested...")
    else:
        click.echo("Installing packages...")
        cmd = "DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
            cython3 python3-dev \
            python3-markdown python3-pyxattr python3-jinja2 python3-cffi \
            software-properties-common libsasl2-modules-gssapi-mit npm nodejs \
            libkrb5-dev libldap2-dev libsasl2-dev gawk libncurses5-dev \
            rsync attr wget unzip"
        click.echo("Running: %s" % cmd)
        if os.system(cmd):
            raise click.ClickException("Failed to install APT packages")
        if os.system("pip3 install -q --upgrade gssapi falcon humanize ipaddress simplepam user-agents"):
            raise click.ClickException("Failed to install Python packages")
        if os.system("pip3 install -q --pre --upgrade python-ldap"):
            raise click.ClickException("Failed to install python-ldap")

        if not os.path.exists("/usr/lib/nginx/modules/ngx_nchan_module.so"):
            click.echo("Enabling nginx PPA")
            if os.system("add-apt-repository -y ppa:nginx/stable"):
                raise click.ClickException("Failed to add nginx PPA")
            if os.system("apt-get update -q"):
                raise click.ClickException("Failed to update package lists")
            if os.system("apt-get install -y -q libnginx-mod-nchan"):
                raise click.ClickException("Failed to install nchan")
        else:
            click.echo("PPA for nginx already enabled")

        if not os.path.exists("/usr/sbin/nginx"):
            click.echo("Installing nginx from PPA")
            if os.system("apt-get install -y -q nginx"):
                raise click.ClickException("Failed to install nginx")
        else:
            click.echo("Web server nginx already installed")

        cmd = "npm install --silent --no-optional -g nunjucks@2.5.2 nunjucks-date@1.2.0 node-forge bootstrap@4.0.0-alpha.6 jquery timeago tether font-awesome qrcode-svg"
        click.echo("Installing JavaScript packages: %s" % cmd)
        if os.system(cmd):
            raise click.ClickException("Failed to install JavaScript packages")

    if not os.path.exists("/usr/bin/node"):
        os.symlink("/usr/bin/nodejs", "/usr/bin/node")

    if packages_only:
        return

    if "." in common_name:
        logger.info("Using fully qualified hostname %s" % common_name)
    else:
        raise ValueError("Fully qualified hostname not specified as common name, make sure hostname -f works")

    template_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates", "profile")
    click.echo("Using templates from %s" % template_path)

    click.echo("Placing authority files in %s" % directory)

    certificate_url = "http://%s/api/certificate/" % common_name
    click.echo("Setting CA certificate URL to %s" % certificate_url)

    revoked_url = "http://%s/api/revoked/" % common_name
    click.echo("Setting revocation list URL to %s" % revoked_url)

    responder_url = "http://%s/api/ocsp/" % common_name
    click.echo("Setting OCSP responder URL to %s" % responder_url)


    # Expand variables
    assets_dir = os.path.join(directory, "assets")
    ca_key = os.path.join(directory, "ca_key.pem")
    ca_req = os.path.join(directory, "ca_req.pem")
    ca_cert = os.path.join(directory, "ca_cert.pem")
    self_key = os.path.join(directory, "self_key.pem")
    sqlite_path = os.path.join(directory, "meta", "db.sqlite")
    distinguished_name = cn_to_dn(title, common_name, o=organization, ou=organizational_unit)
    dhparam_path = "/etc/ssl/dhparam.pem"

    # Builder variables
    dhgroup = "ecp384" if elliptic_curve else "modp2048"

    try:
        pwd.getpwnam("certidude")
        click.echo("User 'certidude' already exists")
    except KeyError:
        cmd = "adduser", "--system", "--no-create-home", "--group", "certidude"
        if subprocess.call(cmd):
            raise click.ClickException("Failed to create system user 'certidude'")

    if os.path.exists(kerberos_keytab):
        click.echo("Service principal keytab found in '%s'" % kerberos_keytab)
    else:
        click.echo("To use 'kerberos' authentication backend join the domain , create service principal and provision authority again:")
        click.echo()
        click.echo("  kinit administrator@EXAMPLE.LAN")
        click.echo("  net ads join -k")
        click.echo("  KRB5_KTNAME=FILE:%s net ads keytab add HTTP -P" % kerberos_keytab)
        click.echo("  kdestroy")
        click.echo("  chown %s %s" % (username, kerberos_keytab))
        click.echo("  mv /etc/certidude/server.conf /etc/certidude/server.backup")
        click.echo("  certidude setup authority")
        click.echo()


    for interval in ("hourly", "daily"):
        if not os.path.exists("/etc/cron.%s/certidude" % interval):
            with open("/etc/cron.%s/certidude" % interval, "w") as fh:
                fh.write("#!/bin/bash\nLANG=C.UTF-8 certidude cron %s\n" % interval)
            os.chmod("/etc/cron.%s/certidude" % interval, 0o755)
            click.echo("Created /etc/cron.%s/certidude" % interval)

    if os.path.exists("/etc/krb5.keytab") and os.path.exists("/etc/samba/smb.conf"):
        # Fetch Kerberos ticket for system account
        cp = ConfigParser()
        cp.read("/etc/samba/smb.conf")
        realm = cp.get("global", "realm")
        domain = realm.lower()
        name = cp.get("global", "netbios name")
        base = ",".join(["dc=" + j for j in domain.split(".")])
    else:
        click.echo("Warning: /etc/krb5.keytab or /etc/samba/smb.conf not found, Kerberos unconfigured")

    letsencrypt_fullchain = "/etc/letsencrypt/live/%s/fullchain.pem" % common_name
    letsencrypt_privkey = "/etc/letsencrypt/live/%s/privkey.pem" % common_name
    letsencrypt = os.path.exists(letsencrypt_fullchain)

    builder_path = os.path.join(os.path.realpath(os.path.dirname(__file__)), "builder")
    script_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), "templates", "script")

    static_path = os.path.join(os.path.realpath(os.path.dirname(__file__)), "static")
    certidude_path = sys.argv[0]

    click.echo("Generating: %s" % nginx_config.name)
    nginx_config.write(env.get_template("server/nginx.conf").render(vars()))
    nginx_config.close()
    if not os.path.exists("/etc/nginx/sites-enabled/certidude.conf"):
        os.symlink("../sites-available/certidude.conf", "/etc/nginx/sites-enabled/certidude.conf")
        click.echo("Symlinked %s -> /etc/nginx/sites-enabled/" % nginx_config.name)
    if os.path.exists("/etc/nginx/sites-enabled/default"):
        os.unlink("/etc/nginx/sites-enabled/default")
    if os.path.exists("/etc/systemd"):
        if os.path.exists("/etc/systemd/system/certidude.service"):
            click.echo("File /etc/systemd/system/certidude.service already exists, remove to regenerate")
        else:
            with open("/etc/systemd/system/certidude.service", "w") as fh:
                fh.write(env.get_template("server/systemd.service").render(vars()))
            click.echo("File /etc/systemd/system/certidude.service created")
            os.system("systemctl daemon-reload")
    else:
        raise NotImplementedError("Not systemd based OS, don't know how to set up initscripts")

    # Set umask to 0022
    os.umask(0o022)
    assert os.getuid() == 0 and os.getgid() == 0

    bootstrap_pid = os.fork()
    if not bootstrap_pid:

        # Create what's usually /var/lib/certidude
        if not os.path.exists(directory):
            os.makedirs(directory)
        assert os.stat(directory).st_mode == 0o40755

        # Create bundle directories
        bundle_js = os.path.join(assets_dir, "js", "bundle.js")
        bundle_css = os.path.join(assets_dir, "css", "bundle.css")
        for path in bundle_js, bundle_css:
            subdir = os.path.dirname(path)
            if not os.path.exists(subdir):
                click.echo("Creating directory %s" % subdir)
                os.makedirs(subdir)

        if skip_assets:
            click.echo("Not attempting to assemble assets as requested...")
        else:
            # Copy fonts
            click.echo("Copying fonts...")
            if os.system("rsync -avq /usr/local/lib/node_modules/font-awesome/fonts/ %s/fonts/" % assets_dir):
                raise click.ClickException("Failed to copy fonts")

            # Compile nunjucks templates
            cmd = 'nunjucks-precompile --include "\.html$" --include "\.ps1$" --include "\.sh$" --include "\.svg$" --include "\.yml$" --include "\.conf$" --include "\.mobileconfig$" %s > %s.part' % (static_path, bundle_js)
            click.echo("Compiling templates: %s" % cmd)
            if os.system(cmd):
                raise click.ClickException("Failed to compile nunjucks templates")

            # Assemble bundle.js
            click.echo("Assembling %s" % bundle_js)
            with open(bundle_js + ".part", "a") as fh:
                for pkg in "jquery/dist/jquery.min.js", "tether/dist/js/*.min.js", "bootstrap/dist/js/*.min.js", "node-forge/dist/forge.all.min.js", "qrcode-svg/dist/qrcode.min.js", "timeago/*.js", "nunjucks/browser/nunjucks-slim.min.js":
                    for j in glob(os.path.join("/usr/local/lib/node_modules", pkg)):
                        click.echo("- Merging: %s" % j)
                        with open(j) as ih:
                            fh.write(ih.read())

            # Assemble bundle.css
            click.echo("Assembling %s" % bundle_css)
            with open(bundle_css + ".part", "w") as fh:
                for pkg in "tether/dist/css/*.min.css", "bootstrap/dist/css/*.min.*css", "font-awesome/css/font-awesome.min.css":
                    for j in glob(os.path.join("/usr/local/lib/node_modules", pkg)):
                        click.echo("- Merging: %s" % j)
                        with open(j) as ih:
                            fh.write(ih.read())

            os.rename(bundle_css + ".part", bundle_css)
            os.rename(bundle_js + ".part", bundle_js)

        assert os.getuid() == 0 and os.getgid() == 0
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("certidude")
        os.setgid(gid)

        # Generate Certidude server config
        if not os.path.exists(const.CONFIG_DIR):
            click.echo("Creating %s" % const.CONFIG_DIR)
            os.makedirs(const.CONFIG_DIR)
        if not os.path.exists(const.SCRIPT_DIR):
            click.echo("Creating %s" % const.SCRIPT_DIR)
            os.makedirs(const.SCRIPT_DIR)

        os.umask(0o177) # 600

        if not os.path.exists(dhparam_path):
            cmd = "openssl", "dhparam", "-out", dhparam_path, str(const.KEY_SIZE)
            subprocess.check_call(cmd)

        if os.path.exists(tls_config.name):
            click.echo("Configuration file %s already exists, not overwriting" % tls_config.name)
        else:
            tls_config.write(env.get_template("nginx-tls.conf").render(locals()))
            click.echo("Generated %s" % tls_config.name)

        if os.path.exists(const.SERVER_CONFIG_PATH):
            click.echo("Configuration file %s already exists, remove to regenerate" % const.SERVER_CONFIG_PATH)
        else:
            push_token = "".join([random.choice(string.ascii_letters + string.digits) for j in range(0,32)])
            with open(const.SERVER_CONFIG_PATH, "w") as fh:
                fh.write(env.get_template("server/server.conf").render(vars()))
            click.echo("Generated %s" % const.SERVER_CONFIG_PATH)

        # Create image builder config
        if os.path.exists(const.BUILDER_CONFIG_PATH):
            click.echo("Image builder config %s already exists, remove to regenerate" % const.BUILDER_CONFIG_PATH)
        else:
            with open(const.BUILDER_CONFIG_PATH, "w") as fh:
                fh.write(env.get_template("server/builder.conf").render(vars()))
            click.echo("File %s created" % const.BUILDER_CONFIG_PATH)

        # Create image builder site script
        if os.path.exists(const.BUILDER_SITE_SCRIPT):
            click.echo("Image builder site customization script %s already exists, remove to regenerate" % const.BUILDER_SITE_SCRIPT)
        else:
            with open(const.BUILDER_SITE_SCRIPT, "w") as fh:
                fh.write(env.get_template("server/site.sh").render(vars()))
            click.echo("File %s created" % const.BUILDER_SITE_SCRIPT)

        # Create signature profile config
        if os.path.exists(const.PROFILE_CONFIG_PATH):
            click.echo("Signature profile config %s already exists, remove to regenerate" % const.PROFILE_CONFIG_PATH)
        else:
            with open(const.PROFILE_CONFIG_PATH, "w") as fh:
                fh.write(env.get_template("server/profile.conf").render(vars()))
            click.echo("File %s created" % const.PROFILE_CONFIG_PATH)

        # Create subdirectories with 770 permissions
        os.umask(0o007)
        for subdir in ("signed", "signed/by-serial", "requests", "revoked", "expired", "meta", "builder"):
            path = os.path.join(directory, subdir)
            if not os.path.exists(path):
                click.echo("Creating directory %s" % path)
                os.mkdir(path)
            else:
                click.echo("Directory already exists %s" % path)
            assert os.stat(path).st_mode == 0o40770, path

        # Create SQLite database file with correct permissions
        os.umask(0o117)
        if not os.path.exists(sqlite_path):
            with open(sqlite_path, "wb") as fh:
                pass

        # Generate and sign CA key
        if not os.path.exists(ca_key) or subordinate and not os.path.exists(ca_req):
            if elliptic_curve:
                click.echo("Generating %s EC key for CA ..." % const.CURVE_NAME)
                public_key, private_key = asymmetric.generate_pair("ec", curve=const.CURVE_NAME)
            else:
                click.echo("Generating %d-bit RSA key for CA ..." % const.KEY_SIZE)
                public_key, private_key = asymmetric.generate_pair("rsa", bit_size=const.KEY_SIZE)

            # Set permission bits to 600
            os.umask(0o177)
            with open(ca_key, 'wb') as f:
                f.write(asymmetric.dump_private_key(private_key, None))

            if subordinate:
                builder = CSRBuilder(distinguished_name, public_key)
                request = builder.build(private_key)
                with open(ca_req + ".part", 'wb') as f:
                    f.write(pem_armor_csr(request))
                os.rename(ca_req + ".part", ca_req)

        if not os.path.exists(ca_cert):
            if subordinate:
                click.echo("Request has been written to %s" % ca_req)
                click.echo()
                click.echo(open(ca_req).read())
                click.echo()
                click.echo("Get it signed and insert signed certificate into %s" % ca_cert)
                click.echo()
                click.echo("  cat > %s" % ca_cert)
                click.echo()
                click.echo("Paste contents and press Ctrl-D, adjust permissions:")
                click.echo()
                click.echo("  chown root:root %s" % ca_cert)
                click.echo("  chmod 0644 %s" % ca_cert)
                click.echo()
                click.echo("To finish setup procedure run 'certidude setup authority' again")
                sys.exit(1) # stop this fork here with error

            # https://technet.microsoft.com/en-us/library/aa998840(v=exchg.141).aspx
            builder = CertificateBuilder(distinguished_name, public_key)
            builder.self_signed = True
            builder.ca = True
            builder.serial_number = generate_serial()

            builder.begin_date = NOW - const.CLOCK_SKEW_TOLERANCE
            builder.end_date = NOW + timedelta(days=authority_lifetime)

            certificate = builder.build(private_key)

            # Set permission bits to 640
            os.umask(0o137)
            with open(ca_cert, 'wb') as f:
                f.write(pem_armor_certificate(certificate))
            click.echo("Authority certificate written to: %s" % ca_cert)

        sys.exit(0) # stop this fork here
    else:

        _, exitcode = os.waitpid(bootstrap_pid, 0)
        if exitcode:
            return 0
        from certidude import authority
        authority.self_enroll(skip_notify=True)
        assert os.path.exists(self_key)
        assert os.path.exists(os.path.join(directory, "signed", common_name) + ".pem")
        assert os.getuid() == 0 and os.getgid() == 0, "Enroll contaminated environment"
        assert os.stat(sqlite_path).st_mode == 0o100660
        assert os.stat(ca_cert).st_mode == 0o100640
        assert os.stat(ca_key).st_mode == 0o100600
        assert os.stat("/etc/nginx/sites-available/certidude.conf").st_mode == 0o100600
        assert os.stat("/etc/certidude/server.conf").st_mode == 0o100600

        click.echo("To enable e-mail notifications install Postfix as sattelite system and set mailer address in %s" % const.SERVER_CONFIG_PATH)
        click.echo()
        click.echo("Use following commands to inspect the newly created files:")
        click.echo()
        click.echo("  openssl x509 -text -noout -in %s | less" % ca_cert)
        click.echo("  openssl rsa -check -in %s" % ca_key)
        click.echo("  openssl verify -CAfile %s %s" % (ca_cert, ca_cert))
        click.echo()
        click.echo("To inspect logs and issued tokens:")
        click.echo()
        click.echo("  echo 'select * from log;' | sqlite3 /var/lib/certidude/meta/db.sqlite")
        click.echo("  echo 'select * from token;' | sqlite3 /var/lib/certidude/meta/db.sqlite")
        click.echo()
        click.echo("Enabling Certidude backend and nginx...")
        os.system("systemctl enable certidude")
        os.system("systemctl enable nginx")
        click.echo("To (re)start services:")
        click.echo()
        click.echo("  systemctl restart certidude")
        click.echo("  systemctl restart nginx")
        click.echo()
        return 0


@click.command("users", help="List users")
def certidude_users():
    from certidude.user import User
    admins = set(User.objects.filter_admins())
    for user in User.objects.all():
        click.echo("%s;%s;%s;%s;%s" % (
            "admin" if user in admins else "user",
            user.name, user.given_name, user.surname, user.mail))


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

    if not hide_requests:
        for common_name, path, buf, csr, submitted, server in authority.list_requests():
            created = 0
            if not verbose:
                click.echo("s " + path)
                continue
            click.echo()
            click.echo(click.style(common_name, fg="blue"))
            click.echo("=" * len(common_name))
            click.echo("State: ? " + click.style("submitted", fg="yellow") + " " + naturaltime(created) + click.style(", %s" %created,  fg="white"))
            click.echo("openssl req -in %s -text -noout" % path)
            dump_common(common_name, path, csr)


    if show_signed:
        for common_name, path, buf, cert, signed, expires in authority.list_signed():
            if not verbose:
                if signed < NOW and NOW < expires:
                    click.echo("v " + path)
                elif expires < NOW:
                    click.echo("e " + path)
                else:
                    click.echo("y " + path)
                continue
            click.echo()
            click.echo(click.style(common_name, fg="blue") + " " + click.style("%040x" % cert.serial_number, fg="white"))
            click.echo("="*(len(common_name)+60))

            if signed < NOW and NOW < expires:
                click.echo("Status: " + click.style("valid", fg="green") + " until " + naturaltime(expires) + click.style(", %s" % expires,  fg="white"))
            elif NOW > expires:
                click.echo("Status: " + click.style("expired", fg="red") + " " + naturaltime(expires) + click.style(", %s" % expires,  fg="white"))
            else:
                click.echo("Status: " + click.style("not valid yet", fg="red") + click.style(", %s" % expires,  fg="white"))
            click.echo()
            click.echo("openssl x509 -in %s -text -noout" % path)
            dump_common(common_name, path, cert)
            for ext in cert["tbs_certificate"]["extensions"]:
                click.echo(" - %s: %s" % (ext["extn_id"].native, repr(ext["extn_value"].native)))

    if show_revoked:
        for common_name, path, buf, cert, signed, expires, revoked, reason in authority.list_revoked():
            if not verbose:
                click.echo("r " + path)
                continue
            click.echo()
            click.echo(click.style(common_name, fg="blue") + " " + click.style("%040x" % cert.serial_number, fg="white"))
            click.echo("="*(len(common_name)+60))

            click.echo("Status: " + click.style("revoked", fg="red") + " due to " + reason + " %s%s" % (naturaltime(NOW-revoked), click.style(", %s" % revoked, fg="white")))
            click.echo("openssl x509 -in %s -text -noout" % path)
            dump_common(common_name, path, cert)
            for ext in cert["tbs_certificate"]["extensions"]:
                click.echo(" - %s: %s" % (ext["extn_id"].native, repr(ext["extn_value"].native)))


@click.command("sign", help="Sign certificate")
@click.argument("common_name")
@click.option("--profile", "-p", default="rw", help="Profile")
@click.option("--overwrite", "-o", default=False, is_flag=True, help="Revoke valid certificate with same CN")
def certidude_sign(common_name, overwrite, profile):
    from certidude import authority, config
    drop_privileges()
    cert = authority.sign(common_name, overwrite=overwrite, profile=config.PROFILES[profile])


@click.command("revoke", help="Revoke certificate")
@click.option("--reason", "-r", default="key_compromise", help="Revocation reason, one of: key_compromise affiliation_changed superseded cessation_of_operation privilege_withdrawn")
@click.argument("common_name")
def certidude_revoke(common_name, reason):
    from certidude import authority
    drop_privileges()
    authority.revoke(common_name, reason)


@click.command("hourly", help="Hourly housekeeping tasks")
def certidude_cron_hourly():
    from certidude import config

    # Update LDAP service ticket if Certidude is joined to domain
    if os.path.exists("/etc/krb5.keytab"):
        if not os.path.exists("/run/certidude"):
            os.makedirs("/run/certidude")
        _, kdc = config.LDAP_ACCOUNTS_URI.rsplit("/", 1)
        cmd = "KRB5CCNAME=/run/certidude/krb5cc.part kinit -k %s$ -S ldap/%s@%s -t /etc/krb5.keytab" % (
            const.HOSTNAME.upper(), kdc, config.KERBEROS_REALM
        )
        click.echo("Executing: %s" % cmd)
        os.system(cmd)
        os.system("chown certidude:certidude /run/certidude/krb5cc.part")
        os.rename("/run/certidude/krb5cc.part", "/run/certidude/krb5cc")


@click.command("daily", help="Daily housekeeping tasks")
def certidude_cron_daily():
    from certidude import authority, config, mailer
    threshold_move = datetime.utcnow() - const.CLOCK_SKEW_TOLERANCE
    threshold_notify = datetime.utcnow() + timedelta(hours=48)
    expired = []
    about_to_expire = []

    # Collect certificates which have expired and are about to expire
    for common_name, path, buf, cert, signed, expires in authority.list_signed():
        if expires < threshold_move:
            expired.append((common_name, path, cert))
        elif expires < threshold_notify:
            about_to_expire.append((common_name, path, cert))

    # Send e-mail notifications
    if expired or about_to_expire:
        mailer.send("expiration-notification.md", **locals())

    # Move valid, but now expired certificates
    for common_name, path, cert in expired:
        expired_path = os.path.join(config.EXPIRED_DIR, "%040x.pem" % cert.serial_number)
        click.echo("Moving %s to %s" % (path, expired_path))
        os.rename(path, expired_path)
        os.remove(os.path.join(config.SIGNED_BY_SERIAL_DIR, "%040x.pem" % cert.serial_number))

    # Move revoked certificate which have expired
    for common_name, path, buf, cert, signed, expires, revoked, reason in authority.list_revoked():
        if expires < threshold_move:
            expired_path = os.path.join(config.EXPIRED_DIR, "%040x.pem" % cert.serial_number)
            click.echo("Moving %s to %s" % (path, expired_path))
            os.rename(path, expired_path)

    # TODO: Send separate e-mails to subjects


@click.command("serve", help="Run server")
@click.option("-p", "--port", default=8080, help="Listen port")
@click.option("-l", "--listen", default="127.0.1.1", help="Listen address")
@click.option("-f", "--fork", default=False, is_flag=True, help="Fork to background")
def certidude_serve(port, listen, fork):
    from certidude import authority, const, push

    if port == 80:
        click.echo("WARNING: Please run Certidude behind nginx, remote address is assumed to be forwarded by nginx!")

    click.echo("Using configuration from: %s" % const.SERVER_CONFIG_PATH)

    log_handlers = []

    from certidude import config

    click.echo("OCSP responder subnets: %s" % config.OCSP_SUBNETS)
    click.echo("CRL subnets: %s" % config.CRL_SUBNETS)
    click.echo("SCEP subnets: %s" % config.SCEP_SUBNETS)

    click.echo("Loading signature profiles:")
    for profile in config.PROFILES.values():
         click.echo("- %s" % profile)
    click.echo()

    # Rebuild reverse mapping
    for cn, path, buf, cert, signed, expires in authority.list_signed():
        by_serial = os.path.join(config.SIGNED_BY_SERIAL_DIR, "%040x.pem" % cert.serial_number)
        if not os.path.exists(by_serial):
            click.echo("Linking %s to ../%s.pem" % (by_serial, cn))
            os.symlink("../%s.pem" % cn, by_serial)

    # Process directories
    if not os.path.exists(const.RUN_DIR):
        click.echo("Creating: %s" % const.RUN_DIR)
        os.makedirs(const.RUN_DIR)
        os.chmod(const.RUN_DIR, 0o755)

    click.echo("Users subnets: %s" %
        ", ".join([str(j) for j in config.USER_SUBNETS]))
    click.echo("Administrative subnets: %s" %
        ", ".join([str(j) for j in config.ADMIN_SUBNETS]))
    click.echo("Auto-sign enabled for following subnets: %s" %
        ", ".join([str(j) for j in config.AUTOSIGN_SUBNETS]))
    click.echo("Request submissions allowed from following subnets: %s" %
        ", ".join([str(j) for j in config.REQUEST_SUBNETS]))

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

        push.publish("server-started")
        logger.debug("Started Certidude at %s", const.FQDN)

        drop_privileges()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            click.echo("Caught Ctrl-C, exiting...")
            push.publish("server-stopped")
            logger.debug("Shutting down Certidude")
            return


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

@click.command("list", help="List tokens")
def certidude_token_list():
    from certidude import config
    from certidude.tokens import TokenManager
    token_manager = TokenManager(config.TOKEN_DATABASE)
    cols = "uuid", "expires", "subject", "state"
    now = datetime.utcnow()
    for token in token_manager.list(expired=True, used=True):
        token["state"] = "used" if token.get("used") else ("valid" if token.get("expires") > now  else "expired")
        print(";".join([str(token.get(col)) for col in cols]))

@click.command("purge", help="Purge tokens")
@click.option("-a", "--all", default=False, is_flag=True, help="Purge all not only expired tokens")
def certidude_token_purge(all):
    from certidude import config
    from certidude.tokens import TokenManager
    token_manager = TokenManager(config.TOKEN_DATABASE)
    print(token_manager.purge(all))

@click.command("issue", help="Issue token")
@click.option("-m", "--subject-mail", default=None, help="Subject e-mail override")
@click.argument("subject")
def certidude_token_issue(subject, subject_mail):
    from certidude import config
    from certidude.tokens import TokenManager
    from certidude.user import User
    token_manager = TokenManager(config.TOKEN_DATABASE)
    token_manager.issue(None, User.objects.get(subject), subject_mail)


@click.group("strongswan", help="strongSwan helpers")
def certidude_setup_strongswan(): pass

@click.group("openvpn", help="OpenVPN helpers")
def certidude_setup_openvpn(): pass

@click.group("setup", help="Getting started section")
def certidude_setup(): pass

@click.group("token", help="Token management")
def certidude_token(): pass

@click.group("cron", help="Housekeeping tasks")
def certidude_cron(): pass

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
certidude_token.add_command(certidude_token_list)
certidude_token.add_command(certidude_token_purge)
certidude_token.add_command(certidude_token_issue)
certidude_cron.add_command(certidude_cron_hourly)
certidude_cron.add_command(certidude_cron_daily)
entry_point.add_command(certidude_token)
entry_point.add_command(certidude_setup)
entry_point.add_command(certidude_serve)
entry_point.add_command(certidude_enroll)
entry_point.add_command(certidude_sign)
entry_point.add_command(certidude_revoke)
entry_point.add_command(certidude_list)
entry_point.add_command(certidude_cron)
entry_point.add_command(certidude_users)
entry_point.add_command(certidude_test)

if __name__ == "__main__":
    entry_point()
