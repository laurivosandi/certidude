
import falcon
import ipaddress
import json
import re
import types
from datetime import date, time, datetime
from OpenSSL import crypto
from certidude.wrappers import Request, Certificate

def event_source(func):
    def wrapped(self, req, resp, *args, **kwargs):
        if req.get_header("Accept") == "text/event-stream":
            resp.status = falcon.HTTP_SEE_OTHER
            resp.location = req.context.get("ca").push_server + "/ev/" + req.context.get("ca").uuid
            resp.body = "Redirecting to:" + resp.location
            print("Delegating EventSource handling to:", resp.location)
        return func(self, req, resp, *args, **kwargs)
    return wrapped

class MyEncoder(json.JSONEncoder):
    REQUEST_ATTRIBUTES = "signable", "identity", "changed", "common_name", \
        "organizational_unit", "given_name", "surname", "fqdn", "email_address", \
        "key_type", "key_length", "md5sum", "sha1sum", "sha256sum", "key_usage"

    CERTIFICATE_ATTRIBUTES = "revokable", "identity", "changed", "common_name", \
        "organizational_unit", "given_name", "surname", "fqdn", "email_address", \
        "key_type", "key_length", "sha256sum", "serial_number", "key_usage"

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
            if req.get_header("Accept").split(",")[0] == "application/json":
                resp.set_header("Content-Type", "application/json")
                resp.set_header("Content-Disposition", "inline")
                resp.body = json.dumps(r, cls=MyEncoder)
            else:
                resp.body = repr(r)
        return r
    return wrapped

