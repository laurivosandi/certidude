# encoding: utf-8

import falcon
import ipaddress
import logging
import os
from certidude import config
from certidude.common import drop_privileges
from user_agents import parse
from wsgiref.simple_server import make_server, WSGIServer
from setproctitle import setproctitle

class NormalizeMiddleware(object):
    def process_request(self, req, resp, *args):
        req.context["remote_addr"] = ipaddress.ip_address(req.access_route[0])
        if req.user_agent:
            req.context["user_agent"] = parse(req.user_agent)
        else:
            req.context["user_agent"] = "Unknown user agent"


class App(object):
    PORT = 8080
    FORKS = None
    DROP_PRIVILEGES = True

    def __init__(self):
        app = falcon.API(middleware=NormalizeMiddleware())
        app.req_options.auto_parse_form_urlencoded = True
        self.attach(app)

        # Set up log handlers
        log_handlers = []
        if config.LOGGING_BACKEND == "sql":
            from certidude.mysqllog import LogHandler
            from certidude.api.log import LogResource
            uri = config.cp.get("logging", "database")
            log_handlers.append(LogHandler(uri))
        elif config.LOGGING_BACKEND == "syslog":
            from logging.handlers import SysLogHandler
            log_handlers.append(SysLogHandler())
            # Browsing syslog via HTTP is obviously not possible out of the box
        elif config.LOGGING_BACKEND:
            raise ValueError("Invalid logging.backend = %s" % config.LOGGING_BACKEND)
        from certidude.push import EventSourceLogHandler
        log_handlers.append(EventSourceLogHandler())

        for j in logging.Logger.manager.loggerDict.values():
            if isinstance(j, logging.Logger): # PlaceHolder is what?
                if j.name.startswith("certidude."):
                    j.setLevel(logging.DEBUG)
                    for handler in log_handlers:
                        j.addHandler(handler)

        self.server = make_server("127.0.1.1", self.PORT, app, WSGIServer)
        setproctitle("certidude: %s" % self.NAME)

    def run(self):
        if self.DROP_PRIVILEGES:
            drop_privileges()
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            return
        else:
            return

    def fork(self):
        for j in range(self.FORKS):
            if not os.fork():
                self.run()
                return True
        return False



class ReadWriteApp(App):
    NAME = "backend server"

    def attach(self, app):
        from certidude import authority, config
        from certidude.tokens import TokenManager
        from .signed import SignedCertificateDetailResource
        from .request import RequestListResource, RequestDetailResource
        from .lease import LeaseResource, LeaseDetailResource
        from .script import ScriptResource
        from .tag import TagResource, TagDetailResource
        from .attrib import AttributeResource
        from .bootstrap import BootstrapResource
        from .token import TokenResource
        from .session import SessionResource, CertificateAuthorityResource
        from .revoked import RevokedCertificateDetailResource

        # Certificate authority API calls
        app.add_route("/api/certificate/", CertificateAuthorityResource())
        app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource(authority))
        app.add_route("/api/request/{cn}/", RequestDetailResource(authority))
        app.add_route("/api/request/", RequestListResource(authority))
        app.add_route("/api/revoked/{serial_number}/", RevokedCertificateDetailResource(authority))

        token_resource = None
        token_manager = None
        if config.USER_ENROLLMENT_ALLOWED: # TODO: add token enable/disable flag for config
            if config.TOKEN_BACKEND == "sql":
                token_manager = TokenManager(config.TOKEN_DATABASE)
                token_resource = TokenResource(authority, token_manager)
                app.add_route("/api/token/", token_resource)
            elif not config.TOKEN_BACKEND:
                pass
            else:
                raise NotImplementedError("Token backend '%s' not supported" % config.TOKEN_BACKEND)

        app.add_route("/api/", SessionResource(authority, token_manager))

        # Extended attributes for scripting etc.
        app.add_route("/api/signed/{cn}/attr/", AttributeResource(authority, namespace="machine"))
        app.add_route("/api/signed/{cn}/script/", ScriptResource(authority))

        # API calls used by pushed events on the JS end
        app.add_route("/api/signed/{cn}/tag/", TagResource(authority))
        app.add_route("/api/signed/{cn}/lease/", LeaseDetailResource(authority))

        # API call used to delete existing tags
        app.add_route("/api/signed/{cn}/tag/{tag}/", TagDetailResource(authority))

        # Gateways can submit leases via this API call
        app.add_route("/api/lease/", LeaseResource(authority))

        # Bootstrap resource
        app.add_route("/api/bootstrap/", BootstrapResource(authority))

        # Add SCEP handler if we have any whitelisted subnets
        if config.SCEP_SUBNETS:
            from .scep import SCEPResource
            app.add_route("/api/scep/", SCEPResource(authority))
        return app


class ResponderApp(App):
    PORT = 8081
    FORKS = 4
    NAME = "ocsp responder"

    def attach(self, app):
        from certidude import authority
        from .ocsp import OCSPResource
        app.add_sink(OCSPResource(authority), prefix="/api/ocsp")
        return app


class RevocationListApp(App):
    PORT = 8082
    FORKS = 2
    NAME = "crl server"

    def attach(self, app):
        from certidude import authority
        from .revoked import RevocationListResource
        app.add_route("/api/revoked/", RevocationListResource(authority))
        return app


class BuilderApp(App):
    PORT = 8083
    FORKS = 1
    NAME = "image builder"

    def attach(self, app):
        # LEDE image builder resource
        from certidude import authority
        from .builder import ImageBuilderResource
        app.add_route("/api/build/{profile}/{suggested_filename}", ImageBuilderResource())
        return app


class LogApp(App):
    PORT = 8084
    FORKS = 2
    NAME = "log server"

    def attach(self, app):
        from certidude.api.log import LogResource
        uri = config.cp.get("logging", "database")
        app.add_route("/api/log/", LogResource(uri))
        return app
