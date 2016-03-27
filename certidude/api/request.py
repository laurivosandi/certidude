
import click
import falcon
import logging
import ipaddress
import os
from certidude import config, authority, helpers, push, errors
from certidude.auth import login_required, login_optional, authorize_admin
from certidude.decorators import serialize, csrf_protection
from certidude.wrappers import Request, Certificate
from certidude.firewall import whitelist_subnets, whitelist_content_types

logger = logging.getLogger("api")

class RequestListResource(object):
    @serialize
    @login_required
    @authorize_admin
    def on_get(self, req, resp):
        return authority.list_requests()


    @login_optional
    @whitelist_subnets(config.REQUEST_SUBNETS)
    @whitelist_content_types("application/pkcs10")
    def on_post(self, req, resp):
        """
        Submit certificate signing request (CSR) in PEM format
        """

        body = req.stream.read(req.content_length)
        csr = Request(body)

        if not csr.common_name:
            logger.warning("Rejected signing request without common name from %s",
                req.context.get("remote_addr"))
            raise falcon.HTTPBadRequest(
                "Bad request",
                "No common name specified!")

        # Check if this request has been already signed and return corresponding certificte if it has been signed
        try:
            cert = authority.get_signed(csr.common_name)
        except EnvironmentError:
            pass
        else:
            if cert.pubkey == csr.pubkey:
                resp.status = falcon.HTTP_SEE_OTHER
                resp.location = os.path.join(os.path.dirname(req.relative_uri), "signed", csr.common_name)
                return

        # TODO: check for revoked certificates and return HTTP 410 Gone

        # Process automatic signing if the IP address is whitelisted and autosigning was requested
        if req.get_param_as_bool("autosign"):
            for subnet in config.AUTOSIGN_SUBNETS:
                if req.context.get("remote_addr") in subnet:
                    try:
                        resp.set_header("Content-Type", "application/x-x509-user-cert")
                        resp.body = authority.sign(csr).dump()
                        return
                    except EnvironmentError: # Certificate already exists, try to save the request
                        pass
                    break

        # Attempt to save the request otherwise
        try:
            csr = authority.store_request(body)
        except errors.RequestExists:
            # We should stil redirect client to long poll URL below
            pass
        except errors.DuplicateCommonNameError:
            # TODO: Certificate renewal
            logger.warning("Rejected signing request with overlapping common name from %s",
                req.context.get("remote_addr"))
            raise falcon.HTTPConflict(
                "CSR with such CN already exists",
                "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")
        else:
            push.publish("request-submitted", csr.common_name)

        # Wait the certificate to be signed if waiting is requested
        if req.get_param("wait"):
            # Redirect to nginx pub/sub
            url = config.PUSH_LONG_POLL % csr.fingerprint()
            click.echo("Redirecting to: %s"  % url)
            resp.status = falcon.HTTP_SEE_OTHER
            resp.set_header("Location", url.encode("ascii"))
            logger.debug("Redirecting signing request from %s to %s", req.context.get("remote_addr"), url)
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202
            logger.info("Signing request from %s stored", req.context.get("remote_addr"))


class RequestDetailResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        """
        Fetch certificate signing request as PEM
        """
        csr = authority.get_request(cn)
        logger.debug("Signing request %s was downloaded by %s",
            csr.common_name, req.context.get("remote_addr"))
        return csr


    @csrf_protection
    @login_required
    @authorize_admin
    def on_patch(self, req, resp, cn):
        """
        Sign a certificate signing request
        """
        csr = authority.get_request(cn)
        cert = authority.sign(csr, overwrite=True, delete=True)
        os.unlink(csr.path)
        resp.body = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = os.path.join(req.relative_uri, "..", "..", "signed", cn)
        logger.info("Signing request %s signed by %s from %s", csr.common_name,
            req.context.get("user"), req.context.get("remote_addr"))


    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        try:
            authority.delete_request(cn)
            # Logging implemented in the function above
        except EnvironmentError as e:
            resp.body = "No certificate CN=%s found" % cn
            logger.warning("User %s failed to delete signing request %s from %s, reason: %s",
                req.context["user"], cn, req.context.get("remote_addr"), e)
            raise falcon.HTTPNotFound()
