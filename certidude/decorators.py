import click
import ipaddress
import json
import logging
import os
import types
from datetime import date, time, datetime, timedelta
from urlparse import urlparse

logger = logging.getLogger("api")

def csrf_protection(func):
    """
    Protect resource from common CSRF attacks by checking user agent and referrer
    """
    import falcon
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
    import falcon
    def wrapped(self, req, resp, *args, **kwargs):
        if req.get_header("Accept") == "text/event-stream":
            resp.status = falcon.HTTP_SEE_OTHER
            resp.location = req.context.get("ca").push_server + "/ev/" + req.context.get("ca").uuid
            resp.body = "Redirecting to:" + resp.location
        return func(self, req, resp, *args, **kwargs)
    return wrapped

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        from certidude.auth import User
        if isinstance(obj, ipaddress._IPAddressBase):
            return str(obj)
        if isinstance(obj, set):
            return tuple(obj)
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        if isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        if isinstance(obj, timedelta):
            return obj.total_seconds()
        if isinstance(obj, types.GeneratorType):
            return tuple(obj)
        if isinstance(obj, User):
            return dict(name=obj.name, given_name=obj.given_name,
                surname=obj.surname, mail=obj.mail)
        return json.JSONEncoder.default(self, obj)


def serialize(func):
    """
    Falcon response serialization
    """
    import falcon
    def wrapped(instance, req, resp, **kwargs):
        if not req.client_accepts("application/json"):
            logger.debug("Client did not accept application/json")
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json")
        resp.set_header("Cache-Control", "no-cache, no-store, must-revalidate")
        resp.set_header("Pragma", "no-cache")
        resp.set_header("Expires", "0")
        resp.body = json.dumps(func(instance, req, resp, **kwargs), cls=MyEncoder)
    return wrapped

