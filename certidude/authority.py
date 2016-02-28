
import click
import os
import re
import socket
import requests
from OpenSSL import crypto
from certidude import config, push
from certidude.wrappers import Certificate, Request
from certidude.signer import raw_sign
from certidude import errors

RE_HOSTNAME = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"

# https://securityblog.redhat.com/2014/06/18/openssl-privilege-separation-analysis/
# https://jamielinux.com/docs/openssl-certificate-authority/
# http://pycopia.googlecode.com/svn/trunk/net/pycopia/ssl/certs.py

def publish_certificate(func):
    # TODO: Implement e-mail and nginx notifications using hooks
    def wrapped(csr, *args, **kwargs):
        cert = func(csr, *args, **kwargs)
        assert isinstance(cert, Certificate), "notify wrapped function %s returned %s" % (func, type(cert))

        if config.PUSH_PUBLISH:
            url = config.PUSH_PUBLISH % csr.fingerprint()
            click.echo("Publishing certificate at %s ..." % url)
            requests.post(url, data=cert.dump(),
                headers={"User-Agent": "Certidude API", "Content-Type": "application/x-x509-user-cert"})
            push.publish("request-signed", csr.common_name)
        return cert
    return wrapped

def get_request(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name")
    return Request(open(os.path.join(config.REQUESTS_DIR, common_name + ".pem")))

def get_signed(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name")
    return Certificate(open(os.path.join(config.SIGNED_DIR, common_name + ".pem")))

def get_revoked(common_name):
    if not re.match(RE_HOSTNAME, common_name):
        raise ValueError("Invalid common name")
    return Certificate(open(os.path.join(config.SIGNED_DIR, common_name + ".pem")))

def store_request(buf, overwrite=False):
    """
    Store CSR for later processing
    """
    request = crypto.load_certificate_request(crypto.FILETYPE_PEM, buf)
    common_name = request.get_subject().CN
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

    return Request(open(request_path))


def signer_exec(cmd, *bits):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(config.SIGNER_SOCKET_PATH)
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
    push.publish("certificate-revoked", cert.fingerprint())


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
    sock.connect(config.SIGNER_SOCKET_PATH)
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
    request_sha1sum = Request(open(path)).fingerprint()
    os.unlink(path)

    # Publish event at CA channel
    push.publish("request-deleted", request_sha1sum)

    # Write empty certificate to long-polling URL
    requests.delete(config.PUSH_PUBLISH % request_sha1sum,
        headers={"User-Agent": "Certidude API"})

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
            raise FileExistsError("Will not overwrite existing certificate")

    # Sign via signer process
    cert_buf = signer_exec("sign-request", req.dump())
    with open(cert_path + ".part", "wb") as fh:
        fh.write(cert_buf)
    os.rename(cert_path + ".part", cert_path)

    return Certificate(open(cert_path))


@publish_certificate
def sign2(request, overwrite=False, delete=True, lifetime=None):
    """
    Sign directly using private key, this is usually done by root.
    Basic constraints and certificate lifetime are copied from config,
    lifetime may be overridden on the command line,
    other extensions are copied as is.
    """
    cert = raw_sign(
        crypto.load_privatekey(crypto.FILETYPE_PEM, open(config.AUTHORITY_PRIVATE_KEY_PATH).read()),
        crypto.load_certificate(crypto.FILETYPE_PEM, open(config.AUTHORITY_CERTIFICATE_PATH).read()),
        request._obj,
        config.CERTIFICATE_BASIC_CONSTRAINTS,
        lifetime=lifetime or config.CERTIFICATE_LIFETIME)

    path = os.path.join(config.SIGNED_DIR, request.common_name + ".pem")
    if os.path.exists(path):
        if overwrite:
            revoke(request.common_name)
        else:
            raise FileExistsError("File %s already exists!" % path)

    buf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    with open(path + ".part", "wb") as fh:
        fh.write(buf)
    os.rename(path + ".part", path)
    click.echo("Wrote certificate to: %s" % path)
    if delete:
        os.unlink(request.path)
        click.echo("Deleted request: %s" % request.path)

    return Certificate(open(path))

