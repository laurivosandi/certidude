import falcon
import mimetypes
import os
import click
from time import sleep
from certidude import authority
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize, event_source
from certidude.wrappers import Request, Certificate
from certidude import config

class CertificateStatusResource(object):
    """
    openssl ocsp -issuer CAcert_class1.pem -serial 0x<serial no in hex> -url http://localhost -CAfile cacert_both.pem
    """
    def on_post(self, req, resp):
        ocsp_request = req.stream.read(req.content_length)
        for component in decoder.decode(ocsp_request):
            click.echo(component)
        resp.append_header("Content-Type", "application/ocsp-response")
        resp.status = falcon.HTTP_200
        raise NotImplementedError()


class CertificateAuthorityResource(object):
    def on_get(self, req, resp):
        resp.stream = open(config.AUTHORITY_CERTIFICATE_PATH, "rb")
        resp.append_header("Content-Disposition", "attachment; filename=ca.crt")


class SessionResource(object):
    @serialize
    @login_required
    @authorize_admin
    @event_source
    def on_get(self, req, resp):
        return dict(
            username=req.context.get("user"),
            event_channel = config.PUSH_EVENT_SOURCE % config.PUSH_TOKEN,
            autosign_subnets = config.AUTOSIGN_SUBNETS,
            request_subnets = config.REQUEST_SUBNETS,
            admin_subnets=config.ADMIN_SUBNETS,
            admin_users=config.ADMIN_USERS,
            requests=authority.list_requests(),
            signed=authority.list_signed(),
            revoked=authority.list_revoked())


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
    from .revoked import RevocationListResource
    from .signed import SignedCertificateListResource, SignedCertificateDetailResource
    from .request import RequestListResource, RequestDetailResource
    from .lease import LeaseResource
    from .whois import WhoisResource
    from .log import LogResource
    from .tag import TagResource, TagDetailResource
    from .cfg import ConfigResource, ScriptResource

    app = falcon.API()

    # Certificate authority API calls
    app.add_route("/api/ocsp/", CertificateStatusResource())
    app.add_route("/api/certificate/", CertificateAuthorityResource())
    app.add_route("/api/revoked/", RevocationListResource())
    app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource())
    app.add_route("/api/signed/", SignedCertificateListResource())
    app.add_route("/api/request/{cn}/", RequestDetailResource())
    app.add_route("/api/request/", RequestListResource())
    app.add_route("/api/log/", LogResource())
    app.add_route("/api/tag/", TagResource())
    app.add_route("/api/tag/{identifier}/", TagDetailResource())
    app.add_route("/api/config/", ConfigResource())
    app.add_route("/api/script/", ScriptResource())
    app.add_route("/api/", SessionResource())

    # Gateway API calls, should this be moved to separate project?
    app.add_route("/api/lease/", LeaseResource())
    app.add_route("/api/whois/", WhoisResource())

    """
    Set up logging
    """

    from certidude import config
    from certidude.mysqllog import MySQLLogHandler
    from datetime import datetime
    import logging
    import socket
    import json


    class PushLogHandler(logging.Handler):
        def emit(self, record):
            from certidude.push import publish
            publish("log-entry", dict(
                created = datetime.fromtimestamp(record.created),
                message = record.msg % record.args,
                severity = record.levelname.lower()))

    sql_handler = MySQLLogHandler(config.DATABASE_POOL)
    push_handler = PushLogHandler()

    for facility in "api", "cli":
        logger = logging.getLogger(facility)
        logger.setLevel(logging.DEBUG)
        logger.addHandler(sql_handler)
        logger.addHandler(push_handler)


    logging.getLogger("cli").debug("Started Certidude at %s",
        socket.getaddrinfo(socket.gethostname(), 0, flags=socket.AI_CANONNAME)[0][3])

    import atexit

    def exit_handler():
        logging.getLogger("cli").debug("Shutting down Certidude")

    atexit.register(exit_handler)

    return app
