
import click
import os
import random
import re
import requests
import socket
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from certidude import config, push, mailer, const
from certidude.wrappers import Certificate, Request
from certidude import errors
from jinja2 import Template

RE_HOSTNAME =  "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])(@(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))?$"

# https://securityblog.redhat.com/2014/06/18/openssl-privilege-separation-analysis/
# https://jamielinux.com/docs/openssl-certificate-authority/
# http://pycopia.googlecode.com/svn/trunk/net/pycopia/ssl/certs.py

# Cache CA certificate
certificate = Certificate(open(config.AUTHORITY_CERTIFICATE_PATH))

def publish_certificate(func):
    # TODO: Implement e-mail and nginx notifications using hooks
    def wrapped(csr, *args, **kwargs):
        cert = func(csr, *args, **kwargs)
        assert isinstance(cert, Certificate), "notify wrapped function %s returned %s" % (func, type(cert))

        if cert.given_name and cert.surname and cert.email_address:
            recipient = "%s %s <%s>" % (cert.given_name, cert.surname, cert.email_address)
        elif cert.email_address:
            recipient = cert.email_address
        else:
            recipient = None

        mailer.send(
            "certificate-signed.md",
            to=recipient,
            attachments=(cert,),
            certificate=cert)

        if config.PUSH_PUBLISH:
            url = config.PUSH_PUBLISH % csr.fingerprint()
            click.echo("Publishing certificate at %s ..." % url)
            requests.post(url, data=cert.dump(),
                headers={"User-Agent": "Certidude API", "Content-Type": "application/x-x509-user-cert"})

            # For deleting request in the web view, use pubkey modulo
            push.publish("request-signed", cert.common_name)
        return cert
    return wrapped


def get_request(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    return Request(open(os.path.join(config.REQUESTS_DIR, common_name + ".pem")))


def get_signed(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    return Certificate(open(os.path.join(config.SIGNED_DIR, common_name + ".pem")))


def get_revoked(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name %s" % repr(common_name))
    return Certificate(open(os.path.join(config.SIGNED_DIR, common_name + ".pem")))


def store_request(buf, overwrite=False):
    """
    Store CSR for later processing
    """

    if not buf: return # No certificate supplied
    csr = x509.load_pem_x509_csr(buf, backend=default_backend())
    for name in csr.subject:
        if name.oid == NameOID.COMMON_NAME:
            common_name = name.value
            break
    else:
        raise ValueError("No common name in %s" % csr.subject)

    request_path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")

    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name")

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

    req = Request(open(request_path))
    mailer.send("request-stored.md", attachments=(req,), request=req)
    return req


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
        raise
    return buf


def revoke_certificate(common_name):
    """
    Revoke valid certificate
    """
    cert = get_signed(common_name)
    revoked_filename = os.path.join(config.REVOKED_DIR, "%s.pem" % cert.serial_number)
    os.rename(cert.path, revoked_filename)
    push.publish("certificate-revoked", cert.common_name)

    # Publish CRL for long polls
    if config.PUSH_PUBLISH:
        url = config.PUSH_PUBLISH % "crl"
        click.echo("Publishing CRL at %s ..." % url)
        requests.post(url, data=export_crl(),
            headers={"User-Agent": "Certidude API", "Content-Type": "application/x-pem-file"})

    mailer.send("certificate-revoked.md", attachments=(cert,), certificate=cert)


def list_requests(directory=config.REQUESTS_DIR):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            yield Request(open(os.path.join(directory, filename)))


def list_signed(directory=config.SIGNED_DIR):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            yield Certificate(open(os.path.join(directory, filename)))


def list_revoked(directory=config.REVOKED_DIR):
    for filename in os.listdir(directory):
        if filename.endswith(".pem"):
            yield Certificate(open(os.path.join(directory, filename)))


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

    path = os.path.join(config.REQUESTS_DIR, common_name + ".pem")
    request = Request(open(path))
    os.unlink(path)

    # Publish event at CA channel
    push.publish("request-deleted", request.common_name)

    # Write empty certificate to long-polling URL
    requests.delete(config.PUSH_PUBLISH % request.fingerprint(),
        headers={"User-Agent": "Certidude API"})

def generate_ovpn_bundle(common_name, owner=None):
    # Construct private key
    click.echo("Generating 4096-bit RSA key...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(k, v) for k, v in (
            (NameOID.COMMON_NAME, common_name),
            (NameOID.GIVEN_NAME, owner and owner.given_name),
            (NameOID.SURNAME, owner and owner.surname),
        ) if v
    ]))

    # Sign CSR
    cert = sign(Request(
        csr.sign(key, hashes.SHA512(), default_backend()).public_bytes(serialization.Encoding.PEM)), overwrite=True)

    bundle = Template(open(config.OPENVPN_BUNDLE_TEMPLATE).read()).render(
        ca = certificate.dump(),
        key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ),
        cert = cert.dump(),
        crl=export_crl(),
    )
    return bundle, cert

def generate_pkcs12_bundle(common_name, key_size=4096, owner=None):
    """
    Generate private key, sign certificate and return PKCS#12 bundle
    """

    # Construct private key
    click.echo("Generating %d-bit RSA key..." % key_size)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(k, v) for k, v in (
            (NameOID.COMMON_NAME, common_name),
            (NameOID.GIVEN_NAME, owner and owner.given_name),
            (NameOID.SURNAME, owner and owner.surname),
        ) if v
    ]))

    if owner:
        click.echo("Setting e-mail to: %s" % owner.mail)
        csr = csr.add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name(owner.mail)
            ]),
            critical=False)

    # Sign CSR
    cert = sign(Request(
        csr.sign(key, hashes.SHA512(), default_backend()).public_bytes(serialization.Encoding.PEM)), overwrite=True)

    # Generate P12, currently supported only by PyOpenSSL
    from OpenSSL import crypto
    p12 = crypto.PKCS12()
    p12.set_privatekey(
        crypto.load_privatekey(
            crypto.FILETYPE_PEM,
            key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        )
    p12.set_certificate( cert._obj )
    p12.set_ca_certificates([certificate._obj])
    return p12.export(), cert


@publish_certificate
def sign(req, overwrite=False, delete=True):
    """
    Sign certificate signing request via signer process
    """
    cert_path = os.path.join(config.SIGNED_DIR, req.common_name + ".pem")

    # Move existing certificate if necessary
    if os.path.exists(cert_path):
        old_cert = Certificate(open(cert_path))
        if overwrite:
            revoke_certificate(req.common_name)
        elif req.pubkey == old_cert.pubkey:
            return old_cert
        else:
            raise EnvironmentError("Will not overwrite existing certificate")

    # Sign via signer process
    cert_buf = signer_exec("sign-request", req.dump())
    with open(cert_path + ".part", "wb") as fh:
        fh.write(cert_buf)
    os.rename(cert_path + ".part", cert_path)

    return Certificate(open(cert_path))


@publish_certificate
def sign2(request, private_key, authority_certificate, overwrite=False, delete=True, lifetime=None):
    """
    Sign directly using private key, this is usually done by root.
    Basic constraints and certificate lifetime are copied from config,
    lifetime may be overridden on the command line,
    other extensions are copied as is.
    """

    certificate_path = os.path.join(config.SIGNED_DIR, request.common_name + ".pem")
    if os.path.exists(certificate_path):
        if overwrite:
            revoke_certificate(request.common_name)
        else:
            raise errors.DuplicateCommonNameError("Valid certificate with common name %s already exists" % request.common_name)

    now = datetime.utcnow()
    request_path = os.path.join(config.REQUESTS_DIR, request.common_name + ".pem")
    request = x509.load_pem_x509_csr(open(request_path).read(), default_backend())

    cert = x509.CertificateBuilder(
        ).subject_name(x509.Name([n for n in request.subject])
        ).serial_number(random.randint(
            0x1000000000000000000000000000000000000000,
            0xffffffffffffffffffffffffffffffffffffffff)
        ).issuer_name(authority_certificate.issuer
        ).public_key(request.public_key()
        ).not_valid_before(now - timedelta(hours=1)
        ).not_valid_after(now + timedelta(days=config.CERTIFICATE_LIFETIME)
        ).add_extension(x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False), critical=True
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(request.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(
                        config.CERTIFICATE_AUTHORITY_URL)
                )
            ]),
            critical=False
        ).add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            config.CERTIFICATE_CRL_URL)],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None)
            ]),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                authority_certificate.public_key()),
            critical=False
        )

    # Append subject alternative name, extended key usage flags etc
    for extension in request.extensions:
        if extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            click.echo("Appending subject alt name extension: %s" % extension)
            cert = cert.add_extension(x509.SubjectAlternativeName(extension.value),
                critical=extension.critical)
        if extension.oid == ExtensionOID.EXTENDED_KEY_USAGE:
            click.echo("Appending extended key usage flags extension: %s" % extension)
            cert = cert.add_extension(x509.ExtendedKeyUsage(extension.value),
                critical=extension.critical)


    cert = cert.sign(private_key, hashes.SHA512(), default_backend())

    buf = cert.public_bytes(serialization.Encoding.PEM)
    with open(certificate_path + ".part", "wb") as fh:
        fh.write(buf)
    os.rename(certificate_path + ".part", certificate_path)
    click.echo("Wrote certificate to: %s" % certificate_path)
    if delete:
        os.unlink(request_path)
        click.echo("Deleted request: %s" % request_path)

    return Certificate(open(certificate_path))

