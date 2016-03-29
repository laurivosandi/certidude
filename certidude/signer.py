

import random
import pwd
import socket
import os
import asyncore
import asynchat
from certidude import constants, config
from OpenSSL import crypto

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
import random

DN_WHITELIST = NameOID.COMMON_NAME, NameOID.GIVEN_NAME, NameOID.SURNAME, \
    NameOID.EMAIL_ADDRESS

SERIAL_MIN = 0x1000000000000000000000000000000000000000
SERIAL_MAX = 0xffffffffffffffffffffffffffffffffffffffff

def raw_sign(private_key, ca_cert, request, basic_constraints, lifetime, key_usage=None, extended_key_usage=None):
    """
    Sign certificate signing request directly with private key assuming it's readable by the process
    """

    # Initialize X.509 certificate object
    cert = crypto.X509()
    cert.set_version(2) # This corresponds to X.509v3

    # Set public key
    cert.set_pubkey(request.get_pubkey())

    # Set issuer
    cert.set_issuer(ca_cert.get_subject())

    # Set SKID and AKID extensions
    cert.add_extensions([
        crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject = cert),
        crypto.X509Extension(
            b"authorityKeyIdentifier",
            False,
            b"keyid:always",
            issuer = ca_cert),
        crypto.X509Extension(
            b"authorityInfoAccess",
            False,
            ("caIssuers;URI: %s" % config.CERTIFICATE_AUTHORITY_URL).encode("ascii")),
        crypto.X509Extension(
            b"crlDistributionPoints",
            False,
            ("URI: %s" % config.CERTIFICATE_CRL_URL).encode("ascii"))
    ])


    # Copy attributes from request
    cert.get_subject().CN = request.get_subject().CN

    if request.get_subject().SN:
        cert.get_subject().SN = request.get_subject().SN
    if request.get_subject().GN:
        cert.get_subject().GN = request.get_subject().GN

    if request.get_subject().OU:
        cert.get_subject().OU = req_subject.OU

    # Copy e-mail, key usage, extended key from request
    for extension in request.get_extensions():
        cert.add_extensions([extension])

    # TODO: Set keyUsage and extendedKeyUsage defaults if none has been provided in the request

    # Override basic constraints if nececssary
    if basic_constraints:
        cert.add_extensions([
            crypto.X509Extension(
                b"basicConstraints",
                True,
                basic_constraints.encode("ascii"))])

    if key_usage:
        try:
            cert.add_extensions([
                crypto.X509Extension(
                    b"keyUsage",
                    True,
                    key_usage.encode("ascii"))])
        except crypto.Error:
            raise ValueError("Invalid value '%s' for keyUsage attribute" % key_usage)

    if extended_key_usage:
        cert.add_extensions([
            crypto.X509Extension(
                b"extendedKeyUsage",
                True,
                extended_key_usage.encode("ascii"))])

    # Set certificate lifetime
    cert.gmtime_adj_notBefore(-3600)
    cert.gmtime_adj_notAfter(lifetime * 24 * 60 * 60)

    # Generate random serial
    cert.set_serial_number(random.randint(SERIAL_MIN, SERIAL_MAX))
    cert.sign(private_key, 'sha512')
    return cert


class SignHandler(asynchat.async_chat):
    def __init__(self, sock, server):
        asynchat.async_chat.__init__(self, sock=sock)
        self.buffer = []
        self.set_terminator(b"\n\n")
        self.server = server

    def parse_command(self, cmd, body=""):
        now = datetime.utcnow()
        if cmd == "export-crl":
            """
            Generate CRL object based on certificate serial number and revocation timestamp
            """

            builder = x509.CertificateRevocationListBuilder(
                ).last_update(now
                ).next_update(now + timedelta(days=1)
                ).issuer_name(self.server.certificate.issuer
                ).add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        self.server.certificate.public_key()), False)

            if body:
                for line in body.split("\n"):
                    serial_number, timestamp = line.split(":")
                    revocation = x509.RevokedCertificateBuilder(
                        ).serial_number(int(serial_number, 16)
                        ).revocation_date(datetime.utcfromtimestamp(int(timestamp))
                        ).add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), False
                        ).build(default_backend())
                    builder = builder.add_revoked_certificate(revocation)

            crl = builder.sign(
                self.server.private_key,
                hashes.SHA512(),
                default_backend())

            self.send(crl.public_bytes(Encoding.PEM))

        elif cmd == "ocsp-request":
            NotImplemented # TODO: Implement OCSP

        elif cmd == "sign-request":
            request = x509.load_pem_x509_csr(body, default_backend())
            subject = x509.Name([n for n in request.subject if n.oid in DN_WHITELIST])

            cert = x509.CertificateBuilder(
                ).subject_name(subject
                ).serial_number(random.randint(SERIAL_MIN, SERIAL_MAX)
                ).issuer_name(self.server.certificate.issuer
                ).public_key(request.public_key()
                ).not_valid_before(now - timedelta(hours=1)
                ).not_valid_after(now + timedelta(days=config.CERTIFICATE_LIFETIME)
                ).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True,
                ).add_extension(x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False), critical=True,
                ).add_extension(x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH]
                ), critical=True,
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
                        self.server.certificate.public_key()),
                    critical=False
                ).sign(self.server.private_key, hashes.SHA512(), default_backend())

            self.send(cert.public_bytes(serialization.Encoding.PEM))
        else:
            raise NotImplementedError("Unknown command: %s" % cmd)

        self.close_when_done()

    def found_terminator(self):
        args = (b"".join(self.buffer)).split("\n", 1)
        self.parse_command(*args)
        self.buffer = []

    def collect_incoming_data(self, data):
        self.buffer.append(data)


class SignServer(asyncore.dispatcher):
    def __init__(self):
        asyncore.dispatcher.__init__(self)

        # Bind to sockets
        if os.path.exists(config.SIGNER_SOCKET_PATH):
            os.unlink(config.SIGNER_SOCKET_PATH)
        os.umask(0o007)
        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.bind(config.SIGNER_SOCKET_PATH)
        self.listen(5)

        # Load CA private key and certificate
        self.private_key = serialization.load_pem_private_key(
            open(config.AUTHORITY_PRIVATE_KEY_PATH).read(),
            password=None, # TODO: Ask password for private key?
            backend=default_backend())
        self.certificate = x509.load_pem_x509_certificate(
            open(config.AUTHORITY_CERTIFICATE_PATH).read(),
            backend=default_backend())

        # Drop privileges
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("nobody")
        os.setgid(gid)
        os.setuid(uid)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = SignHandler(sock, self)

