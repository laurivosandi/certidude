

import random
import socket
import os
import asyncore
import asynchat
from certidude import const, config
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from datetime import datetime, timedelta
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
import random

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
                ).last_update(
                    now - timedelta(minutes=5)
                ).next_update(
                    now + timedelta(seconds=config.REVOCATION_LIST_LIFETIME)
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
            # Only common name and public key are used from request
            request = x509.load_pem_x509_csr(body, default_backend())
            common_name, = request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)

            # If common name is a fully qualified name assume it has to be signed
            # with server certificate flags
            server_flags = "." in common_name.value

            # TODO: For fqdn allow autosign with validation

            extended_key_usage_flags = []
            if server_flags:
                extended_key_usage_flags.append( # IKE intermediate for IPSec
                    x509.ObjectIdentifier("1.3.6.1.5.5.8.2.2"))
                extended_key_usage_flags.append( # OpenVPN server
                    ExtendedKeyUsageOID.SERVER_AUTH)
            else:
                extended_key_usage_flags.append( # OpenVPN client
                    ExtendedKeyUsageOID.CLIENT_AUTH)

            builder = x509.CertificateBuilder(
                ).subject_name(
                    x509.Name([common_name])
                ).serial_number(random.randint(
                    0x1000000000000000000000000000000000000000,
                    0x7fffffffffffffffffffffffffffffffffffffff)
                ).issuer_name(
                    self.server.certificate.issuer
                ).public_key(
                    request.public_key()
                ).not_valid_before(
                    now
                ).not_valid_after(
                    now + timedelta(days=
                        config.SERVER_CERTIFICATE_LIFETIME
                        if server_flags
                        else config.CLIENT_CERTIFICATE_LIFETIME)
                ).add_extension(
                    x509.BasicConstraints(
                        ca=False,
                        path_length=None),
                    critical=True,
                ).add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        key_encipherment=True,
                        content_commitment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False),
                    critical=True,
                ).add_extension(
                    x509.ExtendedKeyUsage(
                        extended_key_usage_flags),
                    critical=True,
                ).add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(
                        request.public_key()),
                    critical=False
                ).add_extension(
                    x509.AuthorityInformationAccess([
                        x509.AccessDescription(
                            AuthorityInformationAccessOID.CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                config.AUTHORITY_CERTIFICATE_URL)
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
                )

            # OpenVPN uses CN while StrongSwan uses SAN
            if server_flags:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(
                        [x509.DNSName(common_name.value)]
                    ),
                    critical=False
                )

            cert = builder.sign(self.server.private_key, hashes.SHA512(), default_backend())

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

import signal
import click

class SignServer(asyncore.dispatcher):
    def __init__(self):
        asyncore.dispatcher.__init__(self)

        if os.path.exists(const.SIGNER_SOCKET_PATH):
            os.unlink(const.SIGNER_SOCKET_PATH)

        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.bind(const.SIGNER_SOCKET_PATH)
        self.listen(5)

        # Load CA private key and certificate
        click.echo("Signer reading private key from %s" % config.AUTHORITY_PRIVATE_KEY_PATH)
        self.private_key = serialization.load_pem_private_key(
            open(config.AUTHORITY_PRIVATE_KEY_PATH).read(),
            password=None, # TODO: Ask password for private key?
            backend=default_backend())
        click.echo("Signer reading certificate from %s" % config.AUTHORITY_CERTIFICATE_PATH)
        self.certificate = x509.load_pem_x509_certificate(
            open(config.AUTHORITY_CERTIFICATE_PATH).read(),
            backend=default_backend())


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = SignHandler(sock, self)

