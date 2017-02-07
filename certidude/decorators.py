import falcon
import ipaddress
import json
import logging
import re
import types
from datetime import date, time, datetime
from OpenSSL import crypto
from certidude.auth import User
from certidude.wrappers import Request, Certificate
from urlparse import urlparse

logger = logging.getLogger("api")

def csrf_protection(func):
    """
    Protect resource from common CSRF attacks by checking user agent and referrer
    """
    def wrapped(self, req, resp, *args, **kwargs):
        # Assume curl and python-requests are used intentionally
        if req.user_agent.startswith("curl/") or req.user_agent.startswith("python-requests/"):
            return func(self, req, resp, *args, **kwargs)

        # For everything else assert referrer
        referrer = req.headers.get("REFERER")


        if referrer:
            scheme, netloc, path, params, query, fragment = urlparse(referrer)
            if ":" in netloc:
                host, port = netloc.split(":", 1)
            else:
                host, port = netloc, None
            if host == req.host:
                return func(self, req, resp, *args, **kwargs)

        # Kaboom!
        logger.warning(u"Prevented clickbait from '%s' with user agent '%s'",
            referrer or "-", req.user_agent)
        raise falcon.HTTPForbidden("Forbidden",
            "No suitable UA or referrer provided, cross-site scripting disabled")
    return wrapped


def event_source(func):
    def wrapped(self, req, resp, *args, **kwargs):
        if req.get_header("Accept") == "text/event-stream":
            resp.status = falcon.HTTP_SEE_OTHER
            resp.location = req.context.get("ca").push_server + "/ev/" + req.context.get("ca").uuid
            resp.body = "Redirecting to:" + resp.location
        return func(self, req, resp, *args, **kwargs)
    return wrapped

class MyEncoder(json.JSONEncoder):
    REQUEST_ATTRIBUTES = "is_client", "identity", "changed", "common_name", \
        "organizational_unit", "fqdn", \
        "key_type", "key_length", "md5sum", "sha1sum", "sha256sum", "key_usage"

    CERTIFICATE_ATTRIBUTES = "revokable", "identity", "common_name", \
        "organizational_unit", "fqdn", \
        "key_type", "key_length", "sha256sum", "serial_number", "key_usage", \
        "signed", "expires"

    def default(self, obj):
        if isinstance(obj, crypto.X509Name):
            try:
                return ", ".join(["%s=%s" % (k.decode("ascii"),v.decode("utf-8")) for k, v in obj.get_components()])
            except UnicodeDecodeError: # Work around old buggy pyopenssl
                return ", ".join(["%s=%s" % (k.decode("ascii"),v.decode("iso8859")) for k, v in obj.get_components()])
        if isinstance(obj, ipaddress._IPAddressBase):
            return str(obj)
        if isinstance(obj, set):
            return tuple(obj)
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        if isinstance(obj, types.GeneratorType):
            return tuple(obj)
        if isinstance(obj, Request):
            return dict([(key, getattr(obj, key)) for key in self.REQUEST_ATTRIBUTES \
                if hasattr(obj, key) and getattr(obj, key)])
        if isinstance(obj, Certificate):
            return dict([(key, getattr(obj, key)) for key in self.CERTIFICATE_ATTRIBUTES \
                if hasattr(obj, key) and getattr(obj, key)])
        if isinstance(obj, User):
            return dict(name=obj.name, given_name=obj.given_name,
                surname=obj.surname, mail=obj.mail)
        if hasattr(obj, "serialize"):
            return obj.serialize()
        return json.JSONEncoder.default(self, obj)


def serialize(func):
    """
    Falcon response serialization
    """
    def wrapped(instance, req, resp, **kwargs):
        resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        resp.set_header("Pragma", "no-cache")
        resp.set_header("Expires", "0")
        r = func(instance, req, resp, **kwargs)
        if resp.body is None:
            if req.accept.startswith("application/json"):
                resp.set_header("Content-Type", "application/json")
                resp.set_header("Content-Disposition", "inline")
                resp.body = json.dumps(r, cls=MyEncoder)
            elif hasattr(r, "content_type") and req.client_accepts(r.content_type):
                resp.set_header("Content-Type", r.content_type)
                resp.set_header("Content-Disposition",
                    ("attachment; filename=%s" % r.suggested_filename).encode("ascii"))
                resp.body = r.dump()
            elif hasattr(r, "content_type"):
                logger.debug(u"Client did not accept application/json or %s, "
                    "client expected %s", r.content_type, req.accept)
                raise falcon.HTTPUnsupportedMediaType(
                    "Client did not accept application/json or %s" % r.content_type)
            else:
                logger.debug(u"Client did not accept application/json, client expected %s", req.accept)
                raise falcon.HTTPUnsupportedMediaType(
                    "Client did not accept application/json")
        return r
    return wrapped

