import os
from OpenSSL import crypto
from datetime import datetime
import hashlib
from Crypto.Util import asn1
import re
import itertools
from configparser import RawConfigParser

# https://jamielinux.com/docs/openssl-certificate-authority/

def subject2dn(subject):
    bits = []
    for j in "C", "S", "L", "O", "OU", "CN":
        if getattr(subject, j, None):
            bits.append("/%s=%s" % (j, getattr(subject, j)))
    return "".join(bits)

class SerialCounter(object):
    def __init__(self, filename):
        self.path = filename
        with open(filename, "r") as fh:
            self.value = int(fh.read(), 16)

    def increment(self):
        self.value += 1
        with open(self.path, "w") as fh:
            fh.write("%04x" % self.value)
        return self.value

class CertificateAuthorityConfig(object):
    """
    Attempt to parse CA-s from openssl.cnf
    """
    
    def __init__(self, *args):
        self._config = RawConfigParser()
        for arg in args:
            self._config.readfp(itertools.chain(["[global]"], open(os.path.expanduser(arg))))

    def instantiate_authority(self, slug):
        section = "CA_" + slug
                
        dirs = dict([(key, self._config.get(section, key)
            if self._config.has_option(section, key) else "")
            for key in ("dir", "certificate", "crl", "certs", "new_certs_dir", "serial", "private_key", "revoked_certs_dir")])
        
        # Variable expansion, eg $dir
        for key, value in dirs.items():
            if "$" in value:
                dirs[key] = re.sub(r'\$([a-z]+)', lambda m:dirs[m.groups()[0]], value)
        
        dirs.pop("dir")
        return CertificateAuthority(slug, **dirs)

    def all_authorities(self):
        for section in self._config:
            if section.startswith("CA_"):
                yield self.instantiate_authority(section[3:])

    def pop_certificate_authority(self):
        def wrapper(func):
            def wrapped(*args, **kwargs):
                slug = kwargs.pop("ca")
                kwargs["ca"] = self.instantiate_authority(slug)
                return func(*args, **kwargs)
            return wrapped
        return wrapper

class CertificateBase:
    def get_issuer_dn(self):
        return subject2dn(self.issuer)

    def get_dn(self):
        return subject2dn(self.subject)
        
    def key_length(self):
        return self._obj.get_pubkey().bits()
        
    def key_type(self):
        if self._obj.get_pubkey().type() == 6:
            return "RSA"
        else:
            raise NotImplementedError()
            
    def get_pubkey(self):            
        pub_asn1=crypto.dump_privatekey(crypto.FILETYPE_ASN1, self._obj.get_pubkey())
        pub_der=asn1.DerSequence()
        pub_der.decode(pub_asn1)
        return pub_der[1]
    
    def get_pubkey_hex(self):
        h = "%x" % self.get_pubkey()
        assert len(h) * 4 == self.key_length(), "%s is not %s" % (len(h)*4, self.key_length())
        return ":".join(re.findall("..", "%x" % self.get_pubkey()))

    def get_pubkey_fingerprint(self):
        import binascii
        return ":".join(re.findall("..", hashlib.sha1(binascii.unhexlify("%x" % self.get_pubkey())).hexdigest()))

class Certificate(CertificateBase):
    def __init__(self, filename, authority=None):
        self.path = os.path.realpath(filename)
        try:
            self._obj = crypto.load_certificate(crypto.FILETYPE_PEM, open(filename).read())
        except crypto.Error:
            click.echo("Failed to parse certificate: %s" % filename)
            raise
        self.not_before = datetime.strptime(self._obj.get_notBefore().decode("ascii"), "%Y%m%d%H%M%SZ")
        self.not_after = datetime.strptime(self._obj.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
        self.subject = self._obj.get_subject()
        self.issuer = self._obj.get_issuer()
        self.serial = self._obj.get_serial_number()
        self.authority = authority
        self.subject_key_identifier = None

    def get_extensions(self):
        for i in range(1, self._obj.get_extension_count()):
            ext = self._obj.get_extension(i)
            yield ext.get_short_name(), str(ext)
        
    def digest(self):
        return self._obj.digest("md5").decode("ascii")
        
    def __eq__(self, other):
        return self.serial == other.serial
        
    def __gt__(self, other):
        return self.serial > other.serial

    def __lt__(self, other):
        return self.serial < other.serial

    def __gte__(self, other):
        return self.serial >= other.serial

    def __lte__(self, other):
        return self.serial <= other.serial

def lock_crl(func):
    def wrapped(ca, *args, **kwargs):
        # TODO: Implement actual locking!
        try:
            crl = crypto.load_crl(crypto.FILETYPE_PEM, open(ca.revocation_list).read())
        except crypto.Error:
            click.echo("Failed to parse CRL in %s" % ca.revocation_list)
            raise
        count = len(crl.get_revoked() or ())
        retval = func(ca, crl, *args, **kwargs)
        if count != len(crl.get_revoked() or ()):
            click.echo("Updating CRL")
            partial = ca.revocation_list + ".part"
            with open(partial, "wb") as fh:
                fh.write(crl.export(
                    ca.certificate._obj,
                    crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca.private_key).read()),
                    crypto.FILETYPE_PEM))
            os.rename(partial, ca.revocation_list)
        return retval
    return wrapped

class Request(CertificateBase):
    def __init__(self, request_path):
        self.path = request_path
        self._obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, open(self.path).read())
        self.subject = self._obj.get_subject()

        """
        pub_asn1=crypto.dump_privatekey(crypto.FILETYPE_ASN1, self._obj.get_pubkey())
        pub_der=asn1.DerSequence()
        pub_der.decode(pub_asn1)
        n=pub_der[1]
        # Get the modulus
        print("public modulus:  %x" % n)
        import binascii
        self.sha_hash = hashlib.sha1(binascii.unhexlify("%x" % n)).hexdigest()
        """
    
    def __repr__(self):
        return "Request(%s)" % repr(self.path)

class CertificateAuthority(object):
    def __init__(self, slug, certificate, crl, certs, new_certs_dir, revoked_certs_dir=None, serial=None, private_key=None):
        self.slug = slug
        self.revocation_list = crl
        self.signed_dir = certs
        self.request_dir = new_certs_dir
        self.revoked_dir = revoked_certs_dir
        self.private_key = private_key
        
        if isinstance(certificate, str):
            self.certificate = Certificate(certificate, self)
        else:
            self.certificate = certificate

        if isinstance(serial, str):
            self.serial_counter=SerialCounter(serial)
        else:
            self.serial_counter=serial

        
    def __repr__(self):
        return "CertificateAuthority(slug=%s)" % repr(self.slug)
        
    def get_request(self, cn):
        return Request(os.path.join(self.request_dir, cn + ".pem"))
        
    def get_certificate(self, cn):
        return Certificate(os.path.join(self.signed_dir, cn + ".pem"))
    
    @lock_crl
    def revoke(self, crl, cn):
        certificate = self.get_certificate(cn)
        revocation = crypto.Revoked()
        revocation.set_rev_date(datetime.now().strftime("%Y%m%d%H%M%SZ").encode("ascii"))
        revocation.set_reason(b"keyCompromise")
        revocation.set_serial(("%x" % certificate.serial).encode("ascii"))
        if self.revoked_dir:
            os.rename(certificate.path, self.revoked_dir)
        else:
            os.unlink(certificate.path)
        crl.add_revoked(revocation)
    
    @lock_crl
    def get_revoked(self, crl):
        for revocation in crl.get_revoked() or ():
            yield int(revocation.get_serial(), 16), \
                revocation.get_reason().decode("ascii"), \
                datetime.strptime(revocation.get_rev_date().decode("ascii"), "%Y%m%d%H%M%SZ")
                            
    def get_signed(self):
        for root, dirs, files in os.walk(self.signed_dir):
            for filename in files:
                yield Certificate(os.path.join(root, filename))
            break

    def get_requests(self):
        for root, dirs, files in os.walk(self.request_dir):
            for filename in files:
                yield Request(os.path.join(root, filename))
    
    def sign(self, request, lifetime=5*365*24*60*60):
        cert = crypto.X509()
        cert.add_extensions([
            crypto.X509Extension(
                b"basicConstraints",
                True,
                b"CA:FALSE, pathlen:0"),
            crypto.X509Extension(
                b"keyUsage",
                True,
                b"digitalSignature, keyEncipherment"),
            crypto.X509Extension(
                b"subjectKeyIdentifier",
                False,
                b"hash",
                subject = self.certificate._obj),
            crypto.X509Extension(
                b"authorityKeyIdentifier",
                False,
                b"keyid:always",
                issuer = self.certificate._obj)])
        cert.set_pubkey(request._obj.get_pubkey())
        cert.set_subject(request._obj.get_subject())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(lifetime)
        cert.set_serial_number(self.serial_counter.increment())
        
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, open(self.private_key).read())
        cert.sign(pkey, 'sha1')
       
        path = os.path.join(self.signed_dir, request.subject.CN + ".pem")
        assert not os.path.exists(path), "File %s already exists!" % path

        buf = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        with open(path + ".part", "wb") as fh:
            fh.write(buf)
        os.rename(path + ".part", path)
        click.echo("Wrote certififcate to: %s" % path)
        os.unlink(request.path)
        click.echo("Deleted request: %s" % request.path)

