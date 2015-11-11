import re
import falcon
import ipaddress
import mimetypes
import os
import json
import types
import click
from time import sleep
from certidude.wrappers import Request, Certificate, CertificateAuthority, \
    CertificateAuthorityConfig
from certidude.auth import login_required
from OpenSSL import crypto
from pyasn1.codec.der import decoder
from datetime import datetime, date
from jinja2 import Environment, PackageLoader, Template

# TODO: Restrictive filesystem permissions result in TemplateNotFound exceptions
env = Environment(loader=PackageLoader("certidude", "templates"))

RE_HOSTNAME = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"

def omit(**kwargs):
    return dict([(key,value) for (key, value) in kwargs.items() if value])

def event_source(func):
    def wrapped(self, req, resp, ca, *args, **kwargs):
        if req.get_header("Accept") == "text/event-stream":
            resp.status = falcon.HTTP_SEE_OTHER
            resp.location = ca.push_server + "/ev/" + ca.uuid
            resp.body = "Redirecting to:" + resp.location
            print("Delegating EventSource handling to:", resp.location)
        return func(self, req, resp, ca, *args, **kwargs)
    return wrapped

def authorize_admin(func):
    def wrapped(self, req, resp, *args, **kwargs):
        authority = kwargs.get("ca")

        # Parse remote IPv4/IPv6 address
        remote_addr = ipaddress.ip_network(req.env["REMOTE_ADDR"])

        # Check for administration subnet whitelist
        print("Comparing:", authority.admin_subnets, "To:", remote_addr)
        for subnet in authority.admin_subnets:
            if subnet.overlaps(remote_addr):
                break
        else:
            raise falcon.HTTPForbidden("Forbidden", "Remote address %s not whitelisted" % remote_addr)

        # Check for username whitelist
        kerberos_username, kerberos_realm = kwargs.get("user")
        if kerberos_username not in authority.admin_users:
            raise falcon.HTTPForbidden("Forbidden", "User %s not whitelisted" % kerberos_username)

        # Retain username, TODO: Better abstraction with username, e-mail, sn, gn?
        kwargs["user"] = kerberos_username
        return func(self, req, resp, *args, **kwargs)
    return wrapped


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
    REQUEST_ATTRIBUTES = "signable", "subject", "changed", "common_name", \
        "organizational_unit", "given_name", "surname", "fqdn", "email_address", \
        "key_type", "key_length", "md5sum", "sha1sum", "sha256sum", "key_usage"

    CERTIFICATE_ATTRIBUTES = "revokable", "subject", "changed", "common_name", \
        "organizational_unit", "given_name", "surname", "fqdn", "email_address", \
        "key_type", "key_length", "sha256sum", "serial_number", "key_usage"

    def default(self, obj):
        if isinstance(obj, crypto.X509Name):
            try:
                return "".join(["/%s=%s" % (k.decode("ascii"),v.decode("utf-8")) for k, v in obj.get_components()])
            except UnicodeDecodeError: # Work around old buggy pyopenssl
                return "".join(["/%s=%s" % (k.decode("ascii"),v.decode("iso8859")) for k, v in obj.get_components()])
        if isinstance(obj, ipaddress._IPAddressBase):
            return str(obj)
        if isinstance(obj, set):
            return tuple(obj)
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        if isinstance(obj, map):
            return tuple(obj)
        if isinstance(obj, types.GeneratorType):
            return tuple(obj)
        if isinstance(obj, Request):
            return dict([(key, getattr(obj, key)) for key in self.REQUEST_ATTRIBUTES \
                if hasattr(obj, key) and getattr(obj, key)])
        if isinstance(obj, Certificate):
            return dict([(key, getattr(obj, key)) for key in self.CERTIFICATE_ATTRIBUTES \
                if hasattr(obj, key) and getattr(obj, key)])
        if isinstance(obj, CertificateAuthority):
            return dict(
                slug = obj.slug,
                certificate = obj.certificate,
                admin_users = obj.admin_users,
                autosign_subnets = obj.autosign_subnets,
                request_subnets = obj.request_subnets,
                admin_subnets=obj.admin_subnets,
                requests=obj.get_requests(),
                signed=obj.get_signed(),
                revoked=obj.get_revoked()
            )
        if hasattr(obj, "serialize"):
            return obj.serialize()
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
        if resp.body is None:
            if not req.client_accepts_json:
                raise falcon.HTTPUnsupportedMediaType(
                    "This API only supports the JSON media type.",
                    href="http://docs.examples.com/api/json")
            resp.set_header("Content-Type", "application/json")
            resp.body = json.dumps(r, cls=MyEncoder)
        return r
    return wrapped


def templatize(path):
    template = env.get_template(path)
    def wrapper(func):
        def wrapped(instance, req, resp, *args, **kwargs):
            assert not req.get_param("unicode") or req.get_param("unicode") == u"✓", "Unicode sanity check failed"
            r = func(instance, req, resp, *args, **kwargs)
            r.pop("self")
            if not resp.body:
                if  req.get_header("Accept") == "application/json":
                    resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
                    resp.set_header("Pragma", "no-cache");
                    resp.set_header("Expires", "0");
                    resp.set_header("Content-Type", "application/json")
                    r.pop("req")
                    r.pop("resp")
                    r.pop("user")
                    resp.body = json.dumps(r, cls=MyEncoder)
                    return r
                else:
                    resp.set_header("Content-Type", "text/html")
                    resp.body = template.render(request=req, **r)
                    return r
        return wrapped
    return wrapper


class CertificateAuthorityBase(object):
    def __init__(self, config):
        self.config = config


class RevocationListResource(CertificateAuthorityBase):
    @pop_certificate_authority
    def on_get(self, req, resp, ca):
        resp.set_header("Content-Type", "application/x-pkcs7-crl")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crl" % ca.slug)
        resp.body = ca.export_crl()


class SignedCertificateDetailResource(CertificateAuthorityBase):
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca, cn):
        path = os.path.join(ca.signed_dir, cn + ".pem")
        if not os.path.exists(path):
            raise falcon.HTTPNotFound()
        resp.stream = open(path, "rb")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" % cn)

    @login_required
    @pop_certificate_authority
    @authorize_admin
    @validate_common_name
    def on_delete(self, req, resp, ca, cn, user):
        ca.revoke(cn)

class SignedCertificateListResource(CertificateAuthorityBase):
    @serialize
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca):
        for j in authority.get_signed():
            yield omit(
                key_type=j.key_type,
                key_length=j.key_length,
                subject=j.distinguished_name,
                cn=j.common_name,
                c=j.country_code,
                st=j.state_or_county,
                l=j.city,
                o=j.organization,
                ou=j.organizational_unit,
                fingerprint=j.fingerprint())


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
        resp.append_header("Content-Type", "application/x-x509-user-cert")
        resp.append_header("Content-Disposition", "attachment; filename=%s.csr" % cn)

    @login_required
    @pop_certificate_authority
    @authorize_admin
    @validate_common_name
    def on_patch(self, req, resp, ca, cn, user):
        """
        Sign a certificate signing request
        """
        csr = ca.get_request(cn)
        cert = ca.sign(csr, overwrite=True, delete=True)
        os.unlink(csr.path)
        resp.body = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = os.path.join(req.relative_uri, "..", "..", "signed", cn)

    @login_required
    @pop_certificate_authority
    @authorize_admin
    def on_delete(self, req, resp, ca, cn, user):
        ca.delete_request(cn)

class RequestListResource(CertificateAuthorityBase):
    @serialize
    @pop_certificate_authority
    def on_get(self, req, resp, ca):
        for j in ca.get_requests():
            yield omit(
                key_type=j.key_type,
                key_length=j.key_length,
                subject=j.distinguished_name,
                cn=j.common_name,
                c=j.country_code,
                st=j.state_or_county,
                l=j.city,
                o=j.organization,
                ou=j.organizational_unit,
                fingerprint=j.fingerprint())

    @pop_certificate_authority
    def on_post(self, req, resp, ca):
        """
        Submit certificate signing request (CSR) in PEM format
        """
        # Parse remote IPv4/IPv6 address
        remote_addr = ipaddress.ip_network(req.env["REMOTE_ADDR"])

        # Check for CSR submission whitelist
        if ca.request_subnets:
            for subnet in ca.request_subnets:
                if subnet.overlaps(remote_addr):
                    break
            else:
               raise falcon.HTTPForbidden("Forbidden", "IP address %s not whitelisted" % remote_addr)

        if req.get_header("Content-Type") != "application/pkcs10":
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only application/pkcs10 content type")

        body = req.stream.read(req.content_length)
        csr = Request(body)

        # Check if this request has been already signed and return corresponding certificte if it has been signed
        try:
            cert_buf = ca.get_certificate(csr.common_name)
        except FileNotFoundError:
            pass
        else:
            cert = Certificate(cert_buf)
            if cert.pubkey == csr.pubkey:
                resp.status = falcon.HTTP_SEE_OTHER
                resp.location = os.path.join(os.path.dirname(req.relative_uri), "signed", csr.common_name)
                return

        # TODO: check for revoked certificates and return HTTP 410 Gone

        # Process automatic signing if the IP address is whitelisted and autosigning was requested
        if req.get_param_as_bool("autosign"):
            for subnet in ca.autosign_subnets:
                if subnet.overlaps(remote_addr):
                    try:
                        resp.append_header("Content-Type", "application/x-x509-user-cert")
                        resp.body = ca.sign(csr).dump()
                        return
                    except FileExistsError: # Certificate already exists, try to save the request
                        pass
                    break

        # Attempt to save the request otherwise
        try:
            request = ca.store_request(body)
        except FileExistsError:
            raise falcon.HTTPConflict(
                "CSR with such CN already exists",
                "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")
        ca.event_publish("request_submitted", request.fingerprint())
        # Wait the certificate to be signed if waiting is requested
        if req.get_param("wait"):
            if ca.push_server:
                # Redirect to nginx pub/sub
                url = ca.push_server + "/lp/" + request.fingerprint()
                click.echo("Redirecting to: %s"  % url)
                resp.status = falcon.HTTP_SEE_OTHER
                resp.append_header("Location", url)
            else:
                click.echo("Using dummy streaming mode, please switch to nginx in production!", err=True)
                # Dummy streaming mode
                while True:
                    sleep(1)
                    if not ca.request_exists(csr.common_name):
                        resp.append_header("Content-Type", "application/x-x509-user-cert")
                        resp.status = falcon.HTTP_201 # Certificate was created
                        resp.body = ca.get_certificate(csr.common_name)
                        break
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202



class CertificateStatusResource(CertificateAuthorityBase):
    """
    openssl ocsp -issuer CAcert_class1.pem -serial 0x<serial no in hex> -url http://localhost -CAfile cacert_both.pem
    """
    def on_post(self, req, resp, ca):
        ocsp_request = req.stream.read(req.content_length)
        for component in decoder.decode(ocsp_request):
            click.echo(component)
        resp.append_header("Content-Type", "application/ocsp-response")
        resp.status = falcon.HTTP_200
        raise NotImplementedError()

class CertificateAuthorityResource(CertificateAuthorityBase):
    @pop_certificate_authority
    def on_get(self, req, resp, ca):
        path = os.path.join(ca.certificate.path)
        resp.stream = open(path, "rb")
        resp.append_header("Content-Disposition", "attachment; filename=%s.crt" % ca.slug)

class IndexResource(CertificateAuthorityBase):
    @serialize
    @login_required
    @pop_certificate_authority
    @authorize_admin
    @event_source
    def on_get(self, req, resp, ca, user):
        return ca

class AuthorityListResource(CertificateAuthorityBase):
    @serialize
    @login_required
    def on_get(self, req, resp, user):
        return dict(
            authorities=(self.config.ca_list), # TODO: Check if user is CA admin
            username=user[0]
        )

class ApplicationConfigurationResource(CertificateAuthorityBase):
    @pop_certificate_authority
    @validate_common_name
    def on_get(self, req, resp, ca, cn):
        ctx = dict(
            cn = cn,
            certificate = ca.get_certificate(cn),
            ca_certificate = open(ca.certificate.path, "r").read())
        resp.append_header("Content-Type", "application/ovpn")
        resp.append_header("Content-Disposition", "attachment; filename=%s.ovpn" % cn)
        resp.body = Template(open("/etc/openvpn/%s.template" % ca.slug).read()).render(ctx)

    @login_required
    @pop_certificate_authority
    @authorize_admin
    @validate_common_name
    def on_put(self, req, resp, user, ca, cn=None):
        pkey_buf, req_buf, cert_buf = ca.create_bundle(cn)

        ctx = dict(
            private_key = pkey_buf,
            certificate = cert_buf,
            ca_certificate = ca.certificate.dump())

        resp.append_header("Content-Type", "application/ovpn")
        resp.append_header("Content-Disposition", "attachment; filename=%s.ovpn" % cn)
        resp.body = Template(open("/etc/openvpn/%s.template" % ca.slug).read()).render(ctx)


class StaticResource(object):
    def __init__(self, root):
        self.root = os.path.realpath(root)

    def __call__(self, req, resp):

        path = os.path.realpath(os.path.join(self.root, req.path[1:]))
        if not path.startswith(self.root):
            raise falcon.HTTPForbidden

        if os.path.isdir(path):
            path = os.path.join(path, "index.html")
        print("Serving:", path)

        if os.path.exists(path):
            content_type, content_encoding = mimetypes.guess_type(path)
            if content_type:
                resp.append_header("Content-Type", content_type)
            if content_encoding:
                resp.append_header("Content-Encoding", content_encoding)
            resp.stream = open(path, "rb")
        else:
            resp.status = falcon.HTTP_404
            resp.body = "File '%s' not found" % req.path



def certidude_app():
    config = CertificateAuthorityConfig()

    app = falcon.API()
    app.add_route("/api/ca/{ca}/ocsp/", CertificateStatusResource(config))
    app.add_route("/api/ca/{ca}/signed/{cn}/openvpn", ApplicationConfigurationResource(config))
    app.add_route("/api/ca/{ca}/certificate/", CertificateAuthorityResource(config))
    app.add_route("/api/ca/{ca}/revoked/", RevocationListResource(config))
    app.add_route("/api/ca/{ca}/signed/{cn}/", SignedCertificateDetailResource(config))
    app.add_route("/api/ca/{ca}/signed/", SignedCertificateListResource(config))
    app.add_route("/api/ca/{ca}/request/{cn}/", RequestDetailResource(config))
    app.add_route("/api/ca/{ca}/request/", RequestListResource(config))
    app.add_route("/api/ca/{ca}/", IndexResource(config))
    app.add_route("/api/ca/", AuthorityListResource(config))
    return app
