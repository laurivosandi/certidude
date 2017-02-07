import os
import hashlib
import re
import click
import io
from certidude import const
from OpenSSL import crypto
from datetime import datetime

def subject2dn(subject):
    bits = []
    for j in "CN", "GN", "SN", "C", "S", "L", "O", "OU":
        if getattr(subject, j, None):
            bits.append("%s=%s" % (j, getattr(subject, j)))
    return ", ".join(bits)

class CertificateBase:
    # Others will cause browsers to import the cert instead of offering to
    # download it
    content_type = "application/x-pem-file"

    def __repr__(self):
        return self.buf

    @property
    def common_name(self):
        return self.subject.CN

    @common_name.setter
    def common_name(self, value):
        self.subject.CN = value

    @property
    def key_usage(self):
        def iterate():
            for key, value, data in self.extensions:
                if key == "keyUsage" or key == "extendedKeyUsage":
                    for bit in value.split(", "):
                        if bit == "1.3.6.1.5.5.8.2.2":
                            yield "IKE Intermediate"
                        else:
                            yield bit
        return ", ".join(iterate())

    @property
    def subject(self):
        return self._obj.get_subject()

    @property
    def issuer(self):
        return self._obj.get_issuer()

    @property
    def issuer_dn(self):
        return subject2dn(self.issuer)

    @property
    def identity(self):
        return subject2dn(self.subject)

    @property
    def key_length(self):
        return self._obj.get_pubkey().bits()

    @property
    def key_type(self):
        if self._obj.get_pubkey().type() == 6:
            return "RSA"
        else:
            raise NotImplementedError()

    @property
    def extensions(self):
        for e in self._obj.get_extensions():
            yield e.get_short_name().decode("ascii"), str(e), e.get_data()

    def set_extensions(self, extensions):
        # X509Req().add_extensions() first invocation takes only effect?!
        assert self._obj.get_extensions() == [], "Extensions already set!"
        self._obj.add_extensions([
            crypto.X509Extension(
                key.encode("ascii"),
                critical,
                value.encode("ascii")) for (key,value,critical) in extensions])

    @property
    def fqdn(self):
        for bit in self.subject_alt_name.split(", "):
            if bit.startswith("DNS:"):
                return bit[4:]
        return ""

    @property
    def pubkey(self):
        from Crypto.Util import asn1
        pubkey_asn1=crypto.dump_privatekey(crypto.FILETYPE_ASN1, self._obj.get_pubkey())
        pubkey_der=asn1.DerSequence()
        pubkey_der.decode(pubkey_asn1)
        zero, modulo, exponent = pubkey_der
        return modulo, exponent

    @property
    def pubkey_hex(self):
        modulo, exponent = self.pubkey
        h = "%x" % modulo
        assert len(h) * 4 == self.key_length, "%s is not %s" % (len(h)*4, self.key_length)
        return re.findall("\d\d", h)

    def fingerprint(self, algorithm="sha256"):
        return hashlib.new(algorithm, self.buf.encode("ascii")).hexdigest()

    @property
    def md5sum(self):
        return self.fingerprint("md5")

    @property
    def sha1sum(self):
        return self.fingerprint("sha1")

    @property
    def sha256sum(self):
        return self.fingerprint("sha256")


class Request(CertificateBase):

    @property
    def suggested_filename(self):
        return self.common_name + ".csr"

    def __init__(self, mixed=None):
        self.buf = None
        self.path = NotImplemented
        self.created = NotImplemented

        if hasattr(mixed, "read"):
            self.path = mixed.name
            _, _, _, _, _, _, _, _, mtime, _ = os.stat(self.path)
            self.created = datetime.fromtimestamp(mtime)
            mixed = mixed.read()
        if isinstance(mixed, str):
            try:
                self.buf = mixed
                mixed = crypto.load_certificate_request(crypto.FILETYPE_PEM, mixed)
            except crypto.Error:
                raise ValueError("Failed to parse: %s" % mixed)
        if isinstance(mixed, crypto.X509Req):
            self._obj = mixed
        else:
            raise ValueError("Can't parse %s (%s) as X.509 certificate signing request!" % (mixed, type(mixed)))

        assert not self.buf or self.buf == self.dump(), "%s is not %s" % (repr(self.buf), repr(self.dump()))

    @property
    def is_server(self):
        return "." in self.common_name

    @property
    def is_client(self):
        return not self.is_server

    def dump(self):
        return crypto.dump_certificate_request(crypto.FILETYPE_PEM, self._obj).decode("ascii")

    def create(self):
        # Generate 4096-bit RSA key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        # Create request
        req = crypto.X509Req()
        req.set_pubkey(key)
        return Request(req)


class Certificate(CertificateBase):

    @property
    def suggested_filename(self):
        return self.common_name + ".crt"

    def __init__(self, mixed):
        self.buf = NotImplemented
        self.path = NotImplemented
        self.changed = NotImplemented

        if hasattr(mixed, "read"):
            self.path = mixed.name
            _, _, _, _, _, _, _, _, mtime, _ = os.stat(self.path)
            self.changed = datetime.fromtimestamp(mtime)
            mixed = mixed.read()
        if isinstance(mixed, str):
            try:
                self.buf = mixed
                mixed = crypto.load_certificate(crypto.FILETYPE_PEM, mixed)
            except crypto.Error:
                raise ValueError("Failed to parse: %s" % mixed)
        if isinstance(mixed, crypto.X509):
            self._obj = mixed
        else:
            raise ValueError("Can't parse %s (%s) as X.509 certificate!" % (mixed, type(mixed)))

        assert not self.buf or self.buf == self.dump(), "%s is not %s" % (self.buf, self.dump())

    @property
    def extensions(self):
        # WTF?!
        for j in range(0, self._obj.get_extension_count()):
            e = self._obj.get_extension(j)
            yield e.get_short_name().decode("ascii"), str(e), e.get_data()

    @property
    def serial_number(self):
        return "%040x" % self._obj.get_serial_number()

    @property
    def serial_number_hex(self):
        return ":".join(re.findall("[0123456789abcdef]{2}", self.serial_number))

    @property
    def signed(self):
        return datetime.strptime(self._obj.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ")

    @property
    def expires(self):
        return datetime.strptime(self._obj.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")

    def dump(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self._obj).decode("ascii")

    def digest(self):
        return self._obj.digest("md5").decode("ascii")

    def __eq__(self, other):
        return self.serial_number == other.serial_number

    def __gt__(self, other):
        return self.signed > other.signed

    def __lt__(self, other):
        return self.signed < other.signed

    def __gte__(self, other):
        return self.signed >= other.signed

    def __lte__(self, other):
        return self.signed <= other.signed

