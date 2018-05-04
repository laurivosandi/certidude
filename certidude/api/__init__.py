# encoding: utf-8

import falcon
import ipaddress
import os
from certidude import config
from user_agents import parse


class NormalizeMiddleware(object):
    def process_request(self, req, resp, *args):
        req.context["remote_addr"] = ipaddress.ip_address(req.access_route[0])
        if req.user_agent:
            req.context["user_agent"] = parse(req.user_agent)
        else:
            req.context["user_agent"] = "Unknown user agent"

def certidude_app(log_handlers=[]):
    from certidude import authority, config
    from .signed import SignedCertificateDetailResource
    from .request import RequestListResource, RequestDetailResource
    from .lease import LeaseResource, LeaseDetailResource
    from .script import ScriptResource
    from .tag import TagResource, TagDetailResource
    from .attrib import AttributeResource
    from .bootstrap import BootstrapResource
    from .token import TokenResource
    from .builder import ImageBuilderResource
    from .session import SessionResource, CertificateAuthorityResource

    app = falcon.API(middleware=NormalizeMiddleware())
    app.req_options.auto_parse_form_urlencoded = True

    # Certificate authority API calls
    app.add_route("/api/certificate/", CertificateAuthorityResource())
    app.add_route("/api/signed/{cn}/", SignedCertificateDetailResource(authority))
    app.add_route("/api/request/{cn}/", RequestDetailResource(authority))
    app.add_route("/api/request/", RequestListResource(authority))
    app.add_route("/api/", SessionResource(authority))

    if config.USER_ENROLLMENT_ALLOWED: # TODO: add token enable/disable flag for config
        app.add_route("/api/token/", TokenResource(authority))

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

    # LEDE image builder resource
    app.add_route("/api/build/{profile}/{suggested_filename}", ImageBuilderResource())

    # Add CRL handler if we have any whitelisted subnets
    if config.CRL_SUBNETS:
        from .revoked import RevocationListResource
        app.add_route("/api/revoked/", RevocationListResource(authority))

    # Add SCEP handler if we have any whitelisted subnets
    if config.SCEP_SUBNETS:
        from .scep import SCEPResource
        app.add_route("/api/scep/", SCEPResource(authority))

    if config.OCSP_SUBNETS:
        from .ocsp import OCSPResource
        app.add_sink(OCSPResource(authority), prefix="/api/ocsp")

    # Set up log handlers
    if config.LOGGING_BACKEND == "sql":
        from certidude.mysqllog import LogHandler
        from certidude.api.log import LogResource
        uri = config.cp.get("logging", "database")
        log_handlers.append(LogHandler(uri))
        app.add_route("/api/log/", LogResource(uri))
    elif config.LOGGING_BACKEND == "syslog":
        from logging.handlers import SysLogHandler
        log_handlers.append(SysLogHandler())
        # Browsing syslog via HTTP is obviously not possible out of the box
    elif config.LOGGING_BACKEND:
        raise ValueError("Invalid logging.backend = %s" % config.LOGGING_BACKEND)

    return app
