
import click
import falcon
import logging
import ipaddress
import os
from certidude import config, authority, helpers, push, errors
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize
from certidude.wrappers import Request, Certificate

logger = logging.getLogger("api")

class RequestListResource(object):
    @serialize
    @authorize_admin
    def on_get(self, req, resp):
        return helpers.list_requests()

    def on_post(self, req, resp):
        """
        Submit certificate signing request (CSR) in PEM format
        """
        # Parse remote IPv4/IPv6 address
        remote_addr = ipaddress.ip_network(req.env["REMOTE_ADDR"])

        # Check for CSR submission whitelist
        if config.REQUEST_SUBNETS:
            for subnet in config.REQUEST_SUBNETS:
                if subnet.overlaps(remote_addr):
                    break
            else:
               logger.warning("Attempted to submit signing request from non-whitelisted address %s", req.env["REMOTE_ADDR"])
               raise falcon.HTTPForbidden("Forbidden", "IP address %s not whitelisted" % remote_addr)

        if req.get_header("Content-Type") != "application/pkcs10":
            raise falcon.HTTPUnsupportedMediaType(
                "This API call accepts only application/pkcs10 content type")

        body = req.stream.read(req.content_length).decode("ascii")
        csr = Request(body)

        # Check if this request has been already signed and return corresponding certificte if it has been signed
        try:
            cert = authority.get_signed(csr.common_name)
        except FileNotFoundError:
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
                if subnet.overlaps(remote_addr):
                    try:
                        resp.set_header("Content-Type", "application/x-x509-user-cert")
                        resp.body = authority.sign(csr).dump()
                        return
                    except FileExistsError: # Certificate already exists, try to save the request
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
            logger.warning("Rejected signing request with overlapping common name from %s", req.env["REMOTE_ADDR"])
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
            resp.set_header("Location", url)
            logger.warning("Redirecting signing request from %s to %s", req.env["REMOTE_ADDR"], url)
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202
            logger.info("Signing request from %s stored", req.env["REMOTE_ADDR"])


class RequestDetailResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        """
        Fetch certificate signing request as PEM
        """
        csr = authority.get_request(cn)
#        if not os.path.exists(path):
#            raise falcon.HTTPNotFound()

        resp.set_header("Content-Type", "application/pkcs10")
        resp.set_header("Content-Disposition", "attachment; filename=%s.csr" % csr.common_name)
        return csr

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
        logger.info("Signing request %s signed by %s from %s", csr.common_name, req.context["user"], req.env["REMOTE_ADDR"])

    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        try:
            authority.delete_request(cn)
        except FileNotFoundError:
            resp.body = "No certificate CN=%s found" % cn
            logger.warning("User %s attempted to delete non-existant signing request %s from %s", req.context["user"], cn, req.env["REMOTE_ADDR"])
            raise falcon.HTTPNotFound()
