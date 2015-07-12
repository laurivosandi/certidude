import re
import falcon
import os
import json
import types
from datetime import datetime, date
from OpenSSL import crypto
from jinja2 import Environment, PackageLoader
env = Environment(loader=PackageLoader('certidude', 'templates'))

RE_HOSTNAME = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"

def omit(**kwargs):
    return dict([(key,value) for (key, value) in kwargs.items() if value])
    
def pop_certificate_authority(func):
    def wrapped(self, req, resp, *args, **kwargs):
        kwargs["ca"] = self.config.instantiate_authority(kwargs["ca"])
        return func(self, req, resp, *args, **kwargs)
    return wrapped

def validate_common_name(func):
    def wrapped(*args, **kwargs):
        if not re.match(RE_HOSTNAME, kwargs["cn"]):
            raise falcon.HTTPBadRequest("Invalid CN", "Common name supplied with request didn't pass the validation regex")
        return func(*args, **kwargs)
    return wrapped
    
class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"
        if isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        if isinstance(obj, map):
            return tuple(obj)
        if isinstance(obj, types.GeneratorType):
            return tuple(obj)
        return json.JSONEncoder.default(self, obj)

def serialize(func):
    """
    Falcon response serialization
    """
    def wrapped(instance, req, resp, **kwargs):
        assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"
        resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        resp.set_header("Pragma", "no-cache");
        resp.set_header("Expires", "0");
        r = func(instance, req, resp, **kwargs)
        if not resp.body:
            if not req.client_accepts_json:
                raise falcon.HTTPUnsupportedMediaType(
                    'This API only supports the JSON media type.',
                    href='http://docs.examples.com/api/json')
            resp.set_header('Content-Type', 'application/json')
            resp.body = json.dumps(r, cls=MyEncoder)
        return r
    return wrapped

def templatize(path):
    template = env.get_template(path)
    def wrapper(func):
        def wrapped(instance, req, resp, **kwargs):
            assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"
            r = func(instance, req, resp, **kwargs)
            if not resp.body:
                if  req.get_header("Accept") == "application/json":
                    resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
                    resp.set_header("Pragma", "no-cache");
                    resp.set_header("Expires", "0");
                    resp.set_header('Content-Type', 'application/json')
                    resp.body = json.dumps(r, cls=MyEncoder)
                    return r
                else:
                    resp.set_header('Content-Type', 'text/html')
                    resp.body = template.render(request=req, **r)
                    return r
        return wrapped
    return wrapper

class CertificateAuthorityBase(object):
    def __init__(self, config):
        self.config = config

class SignedCertificateDetailResource(CertificateAuthorityBase):
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca, cn):
        path = os.path.join(ca.signed_dir, cn + ".pem")
        if not os.path.exists(path):
            raise falcon.HTTPNotFound()
        resp.stream = open(path, "rb")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" % cn)
        
    @pop_certificate_authority
    @validate_common_name
    def on_delete(self, req, resp, ca, cn):
        ca.revoke(cn)

class SignedCertificateListResource(CertificateAuthorityBase):
    @serialize
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca):
        for j in authority.get_signed():
            yield omit(
                key_type=j.key_type(),
                key_length=j.key_length(),
                subject=j.get_dn(),
                issuer=j.get_issuer_dn(),
                cn=j.subject.CN,
                c=j.subject.C,
                st=j.subject.ST,
                l=j.subject.L,
                o=j.subject.O,
                ou=j.subject.OU,
                fingerprint=j.get_pubkey_fingerprint())

class RequestDetailResource(CertificateAuthorityBase):
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca, cn):
        """
        Fetch certificate signing request as PEM
        """
        path = os.path.join(ca.request_dir, cn + ".pem")
        if not os.path.exists(path):
            raise falcon.HTTPNotFound()
        resp.stream = open(path, "rb")
        resp.append_header("Content-Disposition", "attachment; filename=%s.csr" % cn)

    @pop_certificate_authority
    @validate_common_name        
    def on_patch(self, req, resp, ca, cn):
        """
        Sign a certificate signing request
        """
        path = os.path.join(ca.request_dir, cn + ".pem")
        if not os.path.exists(path):
            raise falcon.HTTPNotFound()
        ca.sign(ca.get_request(cn))
        resp.body = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = os.path.join(req.relative_uri, "..", "..", "signed", cn)


class RequestListResource(CertificateAuthorityBase):
    @serialize
    @pop_certificate_authority
    def on_get(self, req, resp, ca):
        for j in ca.get_requests():
            yield omit(
                key_type=j.key_type(),
                key_length=j.key_length(),
                subject=j.get_dn(),
                cn=j.subject.CN,
                c=j.subject.C,
                st=j.subject.ST,
                l=j.subject.L,
                o=j.subject.O,
                ou=j.subject.OU,
                fingerprint=j.get_pubkey_fingerprint())

    @pop_certificate_authority
    def on_post(self, req, resp, ca):
        
        if req.get_header("Content-Type") != "application/pkcs10":
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only application/pkcs10 content type")
        
        # POTENTIAL SECURITY HOLE HERE!
        # Should we sanitize input before we handle it to SSL libs?
        try:
            csr = crypto.load_certificate_request(
                crypto.FILETYPE_PEM, req.stream.read(req.content_length))
        except crypto.Error:
            raise falcon.HTTPBadRequest("Invalid CSR", "Failed to parse request body as PEM")
        
        common_name = csr.get_subject().CN
        
        if not re.match(RE_HOSTNAME, common_name):
            raise falcon.HTTPBadRequest("Invalid CN", "Common name supplied with CSR did not match validation regex")
        
        path = os.path.join(ca.request_dir, common_name + ".pem")
        with open(path, "wb") as fh:
            fh.write(crypto.dump_certificate_request(
                crypto.FILETYPE_PEM, csr))

class CertificateAuthorityResource(CertificateAuthorityBase):
    @templatize("index.html")
    def on_get(self, req, resp, ca):
        return {
            "authority": self.config.instantiate_authority(ca)}
    
        
