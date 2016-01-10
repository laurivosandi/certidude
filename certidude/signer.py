

import random
import pwd
import socket
import os
import asyncore
import asynchat
from datetime import datetime
from OpenSSL import crypto

"""
Signer processes are spawned per private key.
Private key should only be readable by root.
Signer process starts up as root, reads private key,
drops privileges and awaits for opcodes (sign-request, export-crl) at UNIX domain socket
under /run/certidude/signer/
The main motivation behind the concept is to mitigate private key leaks
by confining it to a separate process.

Note that signer process uses basicConstraints, keyUsage and extendedKeyUsage
attributes from openssl.cnf via CertificateAuthority wrapper class.
Hence it's possible only to sign such certificates via the signer process,
making it hard to take advantage of hacked Certidude server, eg. being able to sign
certificate authoirty (basicConstraints=CA:TRUE) or
TLS server certificates (extendedKeyUsage=serverAuth).
"""

EXTENSION_WHITELIST = set(["subjectAltName"])

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

        # TODO: Assert openssl.cnf policy for subject attributes
#        if request.get_subject().O != ca_cert.get_subject().O:
#            raise ValueError("Orgnization name mismatch!")
#        if request.get_subject().C != ca_cert.get_subject().C:
#            raise ValueError("Country mismatch!")

        # Copy attributes from CA
        if ca_cert.get_subject().C:
            cert.get_subject().C  = ca_cert.get_subject().C
        if ca_cert.get_subject().ST:
            cert.get_subject().ST  = ca_cert.get_subject().ST
        if ca_cert.get_subject().L:
            cert.get_subject().L  = ca_cert.get_subject().L
        if ca_cert.get_subject().O:
            cert.get_subject().O  = ca_cert.get_subject().O

        # Copy attributes from request
        cert.get_subject().CN = request.get_subject().CN
        req_subject = request.get_subject()
        if hasattr(req_subject, "OU") and req_subject.OU:
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

        # Generate serial from 0x10000000000000000000 to 0xffffffffffffffffffff
        cert.set_serial_number(random.randint(
            0x1000000000000000000000000000000000000000,
            0xffffffffffffffffffffffffffffffffffffffff))
        cert.sign(private_key, 'sha1')
        return cert


class SignHandler(asynchat.async_chat):
    def __init__(self, sock, server):
        asynchat.async_chat.__init__(self, sock=sock)
        self.buffer = []
        self.set_terminator(b"\n\n")
        self.server = server

    def parse_command(self, cmd, body=""):

        if cmd == "export-crl":
            """
            Generate CRL object based on certificate serial number and revocation timestamp
            """
            crl = crypto.CRL()

            if body:
                for line in body.split("\n"):
                    serial_number, timestamp = line.split(":")
                    # TODO: Assert serial against regex
                    revocation = crypto.Revoked()
                    revocation.set_rev_date(datetime.fromtimestamp(int(timestamp)).strftime("%Y%m%d%H%M%SZ").encode("ascii"))
                    revocation.set_reason(b"keyCompromise")
                    revocation.set_serial(serial_number.encode("ascii"))
                    crl.add_revoked(revocation)

            self.send(crl.export(
                self.server.certificate,
                self.server.private_key,
                crypto.FILETYPE_PEM,
                self.server.revocation_list_lifetime))

        elif cmd == "ocsp-request":
            NotImplemented # TODO: Implement OCSP

        elif cmd == "sign-request":
            request = crypto.load_certificate_request(crypto.FILETYPE_PEM, body)

            for e in request.get_extensions():
                key = e.get_short_name().decode("ascii")
                if key not in EXTENSION_WHITELIST:
                    raise ValueError("Certificte Signing Request contains extension '%s' which is not whitelisted" % key)

            # TODO: Potential exploits during PEM parsing?
            cert = raw_sign(
                self.server.private_key,
                self.server.certificate,
                request,
                basic_constraints=self.server.basic_constraints,
                key_usage=self.server.key_usage,
                extended_key_usage=self.server.extended_key_usage,
                lifetime=self.server.lifetime)
            self.send(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        else:
            raise NotImplementedError("Unknown command: %s" % cmd)

        self.close_when_done()

    def found_terminator(self):
        args = (b"".join(self.buffer)).decode("ascii").split("\n", 1)
        self.parse_command(*args)
        self.buffer = []

    def collect_incoming_data(self, data):
        self.buffer.append(data)


class SignServer(asyncore.dispatcher):
    def __init__(self, socket_path, private_key, certificate, lifetime, basic_constraints, key_usage, extended_key_usage, revocation_list_lifetime):
        asyncore.dispatcher.__init__(self)

        # Bind to sockets
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        os.umask(0o007)
        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.bind(socket_path)
        self.listen(5)

        # Load CA private key and certificate
        self.private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(private_key).read())
        self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate).read())
        self.lifetime = lifetime
        self.revocation_list_lifetime = revocation_list_lifetime
        self.basic_constraints = basic_constraints
        self.key_usage = key_usage
        self.extended_key_usage = extended_key_usage


        # Perhaps perform chroot as well, currently results in
        # (<class 'OpenSSL.crypto.Error'>:[('random number generator', 'SSLEAY_RAND_BYTES', 'PRNG not seeded')
        # probably needs partially populated /dev in chroot

        # Dropping privileges
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam("nobody")
        #os.chroot("/run/certidude/signer/jail")
        os.setgid(gid)
        os.setuid(uid)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = SignHandler(sock, self)

