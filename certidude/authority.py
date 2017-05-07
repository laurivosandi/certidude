
import click
import os
import random
import re
import requests
import hashlib
import socket
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from certidude import config, push, mailer, const
from certidude import errors
from jinja2 import Template
from xattr import getxattr, listxattr

RE_HOSTNAME =  "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(@(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))?$"

# https://securityblog.redhat.com/2014/06/18/openssl-privilege-separation-analysis/
# https://jamielinux.com/docs/openssl-certificate-authority/
# http://pycopia.googlecode.com/svn/trunk/net/pycopia/ssl/certs.py

# Cache CA certificate

with open(config.AUTHORITY_CERTIFICATE_PATH) as fh:
    ca_buf = fh.read()
    ca_cert = x509.load_pem_x509_certificate(ca_buf, default_backend())

def get_request(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")
    try:
        with open(path) as fh:
            buf = fh.read()
            return path, buf, x509.load_pem_x509_csr(buf, default_backend())
    except EnvironmentError:
        raise errors.RequestDoesNotExist("Certificate signing request file %s does not exist" % path)

def get_signed(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    path = os.path.join(config.SIGNED_DIR, common_name + ".pem")
    with open(path) as fh:
        buf = fh.read()
        return path, buf, x509.load_pem_x509_certificate(buf, default_backend())

def get_revoked(serial):
    path = os.path.join(config.REVOKED_DIR, serial + ".pem")
    with open(path) as fh:
        buf = fh.read()
        return path, buf, x509.load_pem_x509_certificate(buf, default_backend())


def get_attributes(cn):
    path, buf, cert = get_signed(cn)
    attribs = dict()
    for key in listxattr(path):
        if not key.startswith("user."):
            continue
        value = getxattr(path, key)
        current = attribs
        if "." in key:
            namespace, key = key.rsplit(".", 1)
            for component in namespace.split("."):
                if component not in current:
                    current[component] = dict()
                current = current[component]
        current[key] = value
    return path, buf, cert, attribs


def store_request(buf, overwrite=False):
    """
    Store CSR for later processing
    """

    if not buf:
        raise ValueError("No signing request supplied")

    csr = x509.load_pem_x509_csr(buf, backend=default_backend())
    common_name, = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    # TODO: validate common name again

    if not re.match(RE_HOSTNAME, common_name.value):
        raise ValueError("Invalid common name")

    request_path = os.path.join(config.REQUESTS_DIR, common_name.value + ".pem")


    # If there is cert, check if it's the same
    if os.path.exists(request_path):
        if open(request_path).read() == buf:
            raise errors.RequestExists("Request already exists")
        else:
            raise errors.DuplicateCommonNameError("Another request with same common name already exists")
    else:
        with open(request_path + ".part", "w") as fh:
            fh.write(buf)
        os.rename(request_path + ".part", request_path)

    attach_csr = buf, "application/x-pem-file", common_name.value + ".csr"
    mailer.send("request-stored.md",
        attachments=(attach_csr,),
        common_name=common_name.value)
    return csr


def signer_exec(cmd, *bits):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(const.SIGNER_SOCKET_PATH)
    sock.send(cmd.encode("ascii"))
    sock.send(b"\n")
    for bit in bits:
        sock.send(bit.encode("ascii"))
    sock.sendall(b"\n\n")
    buf = sock.recv(8192)
    if not buf:
        raise Exception("Connection lost")
    return buf


def revoke(common_name):
    """
    Revoke valid certificate
    """
    path, buf, cert = get_signed(common_name)
    revoked_path = os.path.join(config.REVOKED_DIR, "%x.pem" % cert.serial)
    signed_path = os.path.join(config.SIGNED_DIR, "%s.pem" % common_name)
    os.rename(signed_path, revoked_path)
    push.publish("certificate-revoked", common_name)

    # Publish CRL for long polls
    url = config.LONG_POLL_PUBLISH % "crl"
    click.echo("Publishing CRL at %s ..." % url)
    requests.post(url, data=export_crl(),
        headers={"User-Agent": "Certidude API", "Content-Type": "application/x-pem-file"})

    attach_cert = buf, "application/x-pem-file", common_name + ".crt"
    mailer.send("certificate-revoked.md",
        attachments=(attach_cert,),
        serial_hex="%x" % cert.serial,
        common_name=common_name)
    return revoked_path

def server_flags(cn):
    if config.USER_ENROLLMENT_ALLOWED and not config.USER_MULTIPLE_CERTIFICATES:
        # Common name set to username, used for only HTTPS client validation anyway
        return False
    if "@" in cn:
        # username@hostname is user certificate anyway, can't be server
        return False
    if "." in cn:
        # CN is hostname, if contains dot has to be FQDN, hence a server
        return True
    return False


def list_requests(directory=config.REQUESTS_DIR):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            common_name = filename[:-4]
            path, buf, req = get_request(common_name)
            yield common_name, path, buf, req, server_flags(common_name),

def _list_certificates(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            common_name = filename[:-4]
            path = os.path.join(directory, filename)
            with open(path) as fh:
                buf = fh.read()
                cert = x509.load_pem_x509_certificate(buf, default_backend())
                server = False
                extension = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                for usage in extension.value:
                    if usage == ExtendedKeyUsageOID.SERVER_AUTH: # TODO: IKE intermediate?
                        server = True
                yield common_name, path, buf, cert, server

def list_signed():
    return _list_certificates(config.SIGNED_DIR)

def list_revoked():
    return _list_certificates(config.REVOKED_DIR)

def list_server_names():
    return [cn for cn, path, buf, cert, server in list_signed() if server]

def export_crl():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(const.SIGNER_SOCKET_PATH)
    sock.send(b"export-crl\n")
    for filename in os.listdir(config.REVOKED_DIR):
        if not filename.endswith(".pem"):
            continue
        serial_number = filename[:-4]
        # TODO: Assert serial against regex
        revoked_path = os.path.join(config.REVOKED_DIR, filename)
        # TODO: Skip expired certificates
        s = os.stat(revoked_path)
        sock.send(("%s:%d\n" % (serial_number, s.st_ctime)).encode("ascii"))
    sock.sendall(b"\n")
    return sock.recv(32*1024*1024)


def delete_request(common_name):
    # Validate CN
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name")

    path, buf, csr = get_request(common_name)
    os.unlink(path)

    # Publish event at CA channel
    push.publish("request-deleted", common_name)

    # Write empty certificate to long-polling URL
    requests.delete(
        config.LONG_POLL_PUBLISH % hashlib.sha256(buf).hexdigest(),
        headers={"User-Agent": "Certidude API"})

def generate_ovpn_bundle(common_name, owner=None):
    # Construct private key
    click.echo("Generating %d-bit RSA key..." % const.KEY_SIZE)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=const.KEY_SIZE,
        backend=default_backend()
    )

    key_buf = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(k, v) for k, v in (
            (NameOID.COMMON_NAME, common_name),
        ) if v
    ])).sign(key, hashes.SHA512(), default_backend())

    buf = csr.public_bytes(serialization.Encoding.PEM)

    # Sign CSR
    cert, cert_buf = _sign(csr, buf, overwrite=True)

    bundle = Template(open(config.OPENVPN_PROFILE_TEMPLATE).read()).render(
        ca = ca_buf, key = key_buf, cert = cert_buf, crl=export_crl(),
        servers = list_server_names())
    return bundle, cert

def generate_pkcs12_bundle(common_name, owner=None):
    """
    Generate private key, sign certificate and return PKCS#12 bundle
    """

    # Construct private key
    click.echo("Generating %d-bit RSA key..." % const.KEY_SIZE)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=const.KEY_SIZE,
        backend=default_backend()
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])).sign(key, hashes.SHA512(), default_backend())

    buf = csr.public_bytes(serialization.Encoding.PEM)

    # Sign CSR
    cert, cert_buf = _sign(csr, buf, overwrite=True)

    # Generate P12, currently supported only by PyOpenSSL
    from OpenSSL import crypto
    p12 = crypto.PKCS12()
    p12.set_privatekey(
        crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption())))
    p12.set_certificate(
        crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf))
    p12.set_ca_certificates([
        crypto.load_certificate(crypto.FILETYPE_PEM, ca_buf)])
    return p12.export("1234"), cert


def sign(common_name, overwrite=False):
    """
    Sign certificate signing request via signer process
    """

    req_path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")
    with open(req_path) as fh:
        csr_buf = fh.read()
        csr = x509.load_pem_x509_csr(csr_buf, backend=default_backend())
    common_name, = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

    # Sign with function below
    cert, buf = _sign(csr, csr_buf, overwrite)

    os.unlink(req_path)
    return cert, buf

def _sign(csr, buf, overwrite=False):
    assert buf.startswith("-----BEGIN CERTIFICATE REQUEST-----\n")
    assert isinstance(csr, x509.CertificateSigningRequest)
    from xattr import getxattr, listxattr, setxattr

    common_name, = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cert_path = os.path.join(config.SIGNED_DIR, "%s.pem" % common_name.value)
    renew = False

    attachments = [
        (buf, "application/x-pem-file", common_name.value + ".csr"),
    ]

    revoked_path = None
    overwritten = False

    # Move existing certificate if necessary
    if os.path.exists(cert_path):
        with open(cert_path) as fh:
            prev_buf = fh.read()
            prev = x509.load_pem_x509_certificate(prev_buf, default_backend())
            # TODO: assert validity here again?
            renew = prev.public_key().public_numbers() == csr.public_key().public_numbers()

        if overwrite:
            # TODO: is this the best approach?
            prev_serial_hex = "%x" % prev.serial
            revoked_path = os.path.join(config.REVOKED_DIR, "%s.pem" % prev_serial_hex)
            os.rename(cert_path, revoked_path)
            attachments += [(prev_buf, "application/x-pem-file", "deprecated.crt" if renew else "overwritten.crt")]
            overwritten = True
        else:
            raise EnvironmentError("Will not overwrite existing certificate")

    # Sign via signer process
    cert_buf = signer_exec("sign-request", buf)
    cert = x509.load_pem_x509_certificate(cert_buf, default_backend())
    with open(cert_path + ".part", "wb") as fh:
        fh.write(cert_buf)
    os.rename(cert_path + ".part", cert_path)
    attachments.append((cert_buf, "application/x-pem-file", common_name.value + ".crt"))
    cert_serial_hex = "%x" % cert.serial

    # Copy filesystem attributes to newly signed certificate
    if revoked_path:
        for key in listxattr(revoked_path):
            if not key.startswith("user."):
                continue
            setxattr(cert_path, key, getxattr(revoked_path, key))

    # Send mail
    if renew: # Same keypair
        mailer.send("certificate-renewed.md", **locals())
    else: # New keypair
        mailer.send("certificate-signed.md", **locals())

    url = config.LONG_POLL_PUBLISH % hashlib.sha256(buf).hexdigest()
    click.echo("Publishing certificate at %s ..." % url)
    requests.post(url, data=cert_buf,
        headers={"User-Agent": "Certidude API", "Content-Type": "application/x-x509-user-cert"})

    push.publish("request-signed", common_name.value)
    return cert, cert_buf
