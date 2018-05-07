from __future__ import division, absolute_import, print_function
import click
import logging
import os
import re
import requests
import hashlib
import socket
import sys
from oscrypto import asymmetric
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from certbuilder import CertificateBuilder
from certidude import config, push, mailer, const
from certidude import errors
from certidude.common import cn_to_dn
from crlbuilder import CertificateListBuilder, pem_armor_crl
from csrbuilder import CSRBuilder, pem_armor_csr
from datetime import datetime, timedelta
from jinja2 import Template
from random import SystemRandom
from xattr import getxattr, listxattr, setxattr

logger = logging.getLogger(__name__)
random = SystemRandom()

try:
    from time import time_ns
except ImportError:
    from time import time
    def time_ns():
        return int(time() * 10**9) # 64 bits integer, 32 ns bits

def generate_serial():
    return time_ns() << 56 | random.randint(0, 2**56-1)

# https://securityblog.redhat.com/2014/06/18/openssl-privilege-separation-analysis/
# https://jamielinux.com/docs/openssl-certificate-authority/
# http://pycopia.googlecode.com/svn/trunk/net/pycopia/ssl/certs.py

# Cache CA certificate

with open(config.AUTHORITY_CERTIFICATE_PATH, "rb") as fh:
    certificate_buf = fh.read()
    header, _, certificate_der_bytes = pem.unarmor(certificate_buf)
    certificate = x509.Certificate.load(certificate_der_bytes)
    public_key = asymmetric.load_public_key(certificate["tbs_certificate"]["subject_public_key_info"])
with open(config.AUTHORITY_PRIVATE_KEY_PATH, "rb") as fh:
    key_buf = fh.read()
    header, _, key_der_bytes = pem.unarmor(key_buf)
    private_key = asymmetric.load_private_key(key_der_bytes)

def self_enroll(skip_notify=False):
    assert os.getuid() == 0 and os.getgid() == 0, "Can self-enroll only as root"

    from certidude import const
    common_name = const.FQDN
    directory = os.path.join("/var/lib/certidude", const.FQDN)
    self_key_path = os.path.join(directory, "self_key.pem")

    try:
        path, buf, cert, signed, expires = get_signed(common_name)
        self_public_key = asymmetric.load_public_key(path)
        private_key = asymmetric.load_private_key(self_key_path)
    except FileNotFoundError: # certificate or private key not found
        with open(self_key_path, 'wb') as fh:
            if public_key.algorithm == "ec":
                self_public_key, private_key = asymmetric.generate_pair("ec", curve=public_key.curve)
            elif public_key.algorithm == "rsa":
                self_public_key, private_key = asymmetric.generate_pair("rsa", bit_size=public_key.bit_size)
            else:
                NotImplemented
            fh.write(asymmetric.dump_private_key(private_key, None))
    else:
        now = datetime.utcnow()
        if now + timedelta(days=1) < expires:
            click.echo("Certificate %s still valid, delete to self-enroll again" % path)
            return

    builder = CSRBuilder({"common_name": common_name}, self_public_key)
    request = builder.build(private_key)
    pid = os.fork()
    if not pid:
        from certidude import authority
        from certidude.common import drop_privileges
        drop_privileges()
        assert os.getuid() != 0 and os.getgid() != 0
        path = os.path.join(directory, "requests", common_name + ".pem")
        click.echo("Writing request to %s" % path)
        with open(path, "wb") as fh:
            fh.write(pem_armor_csr(request)) # Write CSR with certidude permissions
        authority.sign(common_name, skip_notify=skip_notify, skip_push=True, overwrite=True, profile=config.PROFILES["srv"])
        sys.exit(0)
    else:
        os.waitpid(pid, 0)
        if os.path.exists("/etc/systemd"):
            os.system("systemctl reload nginx")
        else:
            os.system("service nginx reload")


def get_request(common_name):
    if not re.match(const.RE_COMMON_NAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")
    try:
        with open(path, "rb") as fh:
            buf = fh.read()
            header, _, der_bytes = pem.unarmor(buf)
            return path, buf, CertificationRequest.load(der_bytes), \
                datetime.utcfromtimestamp(os.stat(path).st_ctime)
    except EnvironmentError:
        raise errors.RequestDoesNotExist("Certificate signing request file %s does not exist" % path)

def get_signed(common_name):
    if not re.match(const.RE_COMMON_NAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    path = os.path.join(config.SIGNED_DIR, common_name + ".pem")
    with open(path, "rb") as fh:
        buf = fh.read()
        header, _, der_bytes = pem.unarmor(buf)
        cert = x509.Certificate.load(der_bytes)
        return path, buf, cert, \
            cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None), \
            cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None)

def get_revoked(serial):
    if isinstance(serial, str):
        serial = int(serial, 16)
    path = os.path.join(config.REVOKED_DIR, "%040x.pem" % serial)
    with open(path, "rb") as fh:
        buf = fh.read()
        header, _, der_bytes = pem.unarmor(buf)
        cert = x509.Certificate.load(der_bytes)
        try:
            reason = getxattr(path, "user.revocation.reason").decode("ascii")
        except IOError: # TODO: make sure it's not required
            reason = "key_compromise"
        return path, buf, cert, \
            cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None), \
            cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None), \
            datetime.utcfromtimestamp(os.stat(path).st_ctime), \
            reason


def get_attributes(cn, namespace=None, flat=False):
    path, buf, cert, signed, expires = get_signed(cn)
    attribs = dict()
    for key in listxattr(path):
        key = key.decode("ascii")
        if not key.startswith("user."):
            continue
        if namespace and not key.startswith("user.%s." % namespace):
            continue
        value = getxattr(path, key).decode("utf-8")
        if flat:
            attribs[key[len("user.%s." % namespace):]] = value
        else:
            current = attribs
            if "." in key:
                prefix, key = key.rsplit(".", 1)
                for component in prefix.split("."):
                    if component not in current:
                        current[component] = dict()
                    current = current[component]
            current[key] = value
    return path, buf, cert, attribs


def store_request(buf, overwrite=False, address="", user=""):
    """
    Store CSR for later processing
    """

    if not buf:
        raise ValueError("No signing request supplied")

    if pem.detect(buf):
        header, _, der_bytes = pem.unarmor(buf)
        csr = CertificationRequest.load(der_bytes)
    else:
        csr = CertificationRequest.load(buf)
        buf =  pem_armor_csr(csr)

    common_name = csr["certification_request_info"]["subject"].native["common_name"]

    if not re.match(const.RE_COMMON_NAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))

    request_path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")


    # If there is cert, check if it's the same
    if os.path.exists(request_path) and not overwrite:
        if open(request_path, "rb").read() == buf:
            raise errors.RequestExists("Request already exists")
        else:
            raise errors.DuplicateCommonNameError("Another request with same common name already exists")
    else:
        with open(request_path + ".part", "wb") as fh:
            fh.write(buf)
        os.rename(request_path + ".part", request_path)

    attach_csr = buf, "application/x-pem-file", common_name + ".csr"
    mailer.send("request-stored.md",
        attachments=(attach_csr,),
        common_name=common_name)
    setxattr(request_path, "user.request.address", address)
    setxattr(request_path, "user.request.user", user)
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(address)
    except (socket.herror, OSError): # Failed to resolve hostname or resolved to multiple
        pass
    else:
        setxattr(request_path, "user.request.hostname", hostname)
    return request_path, csr, common_name


def revoke(common_name, reason, user="root"):
    """
    Revoke valid certificate
    """
    signed_path, buf, cert, signed, expires = get_signed(common_name)

    if reason not in ("key_compromise", "ca_compromise", "affiliation_changed",
        "superseded", "cessation_of_operation", "certificate_hold",
        "remove_from_crl", "privilege_withdrawn"):
        raise ValueError("Invalid revocation reason %s" % reason)

    setxattr(signed_path, "user.revocation.reason", reason)
    revoked_path = os.path.join(config.REVOKED_DIR, "%040x.pem" % cert.serial_number)

    logger.info("Revoked certificate %s by %s", common_name, user)

    os.unlink(os.path.join(config.SIGNED_BY_SERIAL_DIR, "%040x.pem" % cert.serial_number))
    os.rename(signed_path, revoked_path)

    push.publish("certificate-revoked", common_name)

    attach_cert = buf, "application/x-pem-file", common_name + ".crt"
    mailer.send("certificate-revoked.md",
        attachments=(attach_cert,),
        serial_hex="%x" % cert.serial_number,
        common_name=common_name)
    return revoked_path


def list_requests(directory=config.REQUESTS_DIR):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            common_name = filename[:-4]
            path, buf, req, submitted = get_request(common_name)
            yield common_name, path, buf, req, submitted, "." in common_name

def _list_certificates(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            path = os.path.join(directory, filename)
            with open(path, "rb") as fh:
                buf = fh.read()
                header, _, der_bytes = pem.unarmor(buf)
                cert = x509.Certificate.load(der_bytes)
                server = False
                for extension in cert["tbs_certificate"]["extensions"]:
                    if extension["extn_id"].native == "extended_key_usage":
                        if "server_auth" in extension["extn_value"].native:
                            server = True
                yield cert.subject.native["common_name"], path, buf, cert, server

def list_signed(directory=config.SIGNED_DIR, common_name=None):
    for filename in os.listdir(directory):
        if not filename.endswith(".pem"):
            continue
        basename = filename[:-4]
        if common_name:
            if common_name.startswith("^"):
                if not re.match(common_name, basename):
                    continue
            else:
                if common_name != basename:
                    continue
        path, buf, cert, signed, expires = get_signed(basename)
        yield basename, path, buf, cert, signed, expires

def list_revoked(directory=config.REVOKED_DIR, limit=0):
    for filename in sorted(os.listdir(directory), reverse=True):
        if filename.endswith(".pem"):
            common_name = filename[:-4]
            path, buf, cert, signed, expired, revoked, reason = get_revoked(common_name)
            yield cert.subject.native["common_name"], path, buf, cert, signed, expired, revoked, reason
        if limit:
            limit -= 1
            if limit <= 0:
                return


def list_server_names():
    return [cn for cn, path, buf, cert, server in list_signed() if server]


def export_crl(pem=True):
    # To migrate older installations run following:
    # for j in /var/lib/certidude/*/revoked/*.pem; do echo $(attr -s 'revocation.reason' -V key_compromise $j); done
    builder = CertificateListBuilder(
        config.AUTHORITY_CRL_URL,
        certificate,
        generate_serial()
    )

    for filename in os.listdir(config.REVOKED_DIR):
        if not filename.endswith(".pem"):
            continue
        serial_number = filename[:-4]
        # TODO: Assert serial against regex
        revoked_path = os.path.join(config.REVOKED_DIR, filename)
        try:
            reason = getxattr(revoked_path, "user.revocation.reason").decode("ascii") # TODO: dedup
        except IOError: # TODO: make sure it's not required
            reason = "key_compromise"

        # TODO: Skip expired certificates
        s = os.stat(revoked_path)
        builder.add_certificate(
            int(filename[:-4], 16),
            datetime.utcfromtimestamp(s.st_ctime),
            reason)

    certificate_list = builder.build(private_key)
    if pem:
        return pem_armor_crl(certificate_list)
    return certificate_list.dump()


def delete_request(common_name, user="root"):
    # Validate CN
    if not re.match(const.RE_COMMON_NAME, common_name):
        raise ValueError("Invalid common name")

    path, buf, csr, submitted = get_request(common_name)
    os.unlink(path)

    logger.info("Rejected signing request %s by %s" % (
        common_name, user))

    # Publish event at CA channel
    push.publish("request-deleted", common_name)

    # Write empty certificate to long-polling URL
    requests.delete(
        config.LONG_POLL_PUBLISH % hashlib.sha256(buf).hexdigest(),
        headers={"User-Agent": "Certidude API"})

def sign(common_name, profile, skip_notify=False, skip_push=False, overwrite=False, signer="root"):
    """
    Sign certificate signing request by it's common name
    """

    req_path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")
    with open(req_path, "rb") as fh:
        csr_buf = fh.read()
        header, _, der_bytes = pem.unarmor(csr_buf)
        csr = CertificationRequest.load(der_bytes)


    # Sign with function below
    cert, buf = _sign(csr, csr_buf, profile, skip_notify, skip_push, overwrite, signer)

    os.unlink(req_path)
    return cert, buf

def _sign(csr, buf, profile, skip_notify=False, skip_push=False, overwrite=False, signer=None):
    # TODO: CRLDistributionPoints, OCSP URL, Certificate URL
    assert buf.startswith(b"-----BEGIN ")
    assert isinstance(csr, CertificationRequest)
    csr_pubkey = asymmetric.load_public_key(csr["certification_request_info"]["subject_pk_info"])
    common_name = csr["certification_request_info"]["subject"].native["common_name"]
    cert_path = os.path.join(config.SIGNED_DIR, "%s.pem" % common_name)
    renew = False

    attachments = [
        (buf, "application/x-pem-file", common_name + ".csr"),
    ]

    revoked_path = None
    overwritten = False

    # Move existing certificate if necessary
    if os.path.exists(cert_path):
        with open(cert_path, "rb") as fh:
            prev_buf = fh.read()
            header, _, der_bytes = pem.unarmor(prev_buf)
            prev = x509.Certificate.load(der_bytes)

            # TODO: assert validity here again?
            renew = \
                asymmetric.load_public_key(prev["tbs_certificate"]["subject_public_key_info"]) == \
                csr_pubkey
                # BUGBUG: is this enough?

        if overwrite:
            # TODO: is this the best approach?
            # TODO: why didn't unittest detect bugs here?
            prev_serial_hex = "%x" % prev.serial_number
            revoked_path = os.path.join(config.REVOKED_DIR, "%040x.pem" % prev.serial_number)
            os.rename(cert_path, revoked_path)
            attachments += [(prev_buf, "application/x-pem-file", "deprecated.crt" if renew else "overwritten.crt")]
            overwritten = True
        else:
            raise FileExistsError("Will not overwrite existing certificate")

    builder = CertificateBuilder(cn_to_dn(common_name, const.FQDN,
        o=certificate["tbs_certificate"]["subject"].native.get("organization_name"),
        ou=profile.ou), csr_pubkey)
    builder.serial_number = generate_serial()

    now = datetime.utcnow()
    builder.begin_date = now - timedelta(minutes=5)
    builder.end_date = now + timedelta(days=profile.lifetime)
    builder.issuer = certificate
    builder.ca = profile.ca
    builder.key_usage = profile.key_usage
    builder.extended_key_usage = profile.extended_key_usage
    builder.subject_alt_domains = [common_name]

    end_entity_cert = builder.build(private_key)
    end_entity_cert_buf = asymmetric.dump_certificate(end_entity_cert)
    with open(cert_path + ".part", "wb") as fh:
        fh.write(end_entity_cert_buf)

    os.rename(cert_path + ".part", cert_path)
    attachments.append((end_entity_cert_buf, "application/x-pem-file", common_name + ".crt"))
    cert_serial_hex = "%x" % end_entity_cert.serial_number

    # Create symlink
    link_name = os.path.join(config.SIGNED_BY_SERIAL_DIR, "%040x.pem" % end_entity_cert.serial_number)
    assert not os.path.exists(link_name), "Certificate with same serial number already exists: %s" % link_name
    os.symlink("../%s.pem" % common_name, link_name)

    # Copy filesystem attributes to newly signed certificate
    if revoked_path:
        for key in listxattr(revoked_path):
            if not key.startswith(b"user."):
                continue
            setxattr(cert_path, key, getxattr(revoked_path, key))

    # Attach signer username
    if signer:
        setxattr(cert_path, "user.signature.username", signer)

    if not skip_notify:
        # Send mail
        if renew: # Same keypair
            mailer.send("certificate-renewed.md", **locals())
        else: # New keypair
            mailer.send("certificate-signed.md", **locals())

    if not skip_push:
        url = config.LONG_POLL_PUBLISH % hashlib.sha256(buf).hexdigest()
        click.echo("Publishing certificate at %s ..." % url)
        requests.post(url, data=end_entity_cert_buf,
            headers={"User-Agent": "Certidude API", "Content-Type": "application/x-x509-user-cert"})
        if renew:
            # TODO: certificate-renewed event
            push.publish("certificate-revoked", common_name)
            push.publish("request-signed", common_name)
        else:
            push.publish("request-signed", common_name)
    return end_entity_cert, end_entity_cert_buf
