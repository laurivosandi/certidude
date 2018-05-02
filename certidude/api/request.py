import click
import falcon
import logging
import json
import os
import hashlib
from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest
from base64 import b64decode
from certidude import config, push, errors
from certidude.decorators import csrf_protection, MyEncoder
from certidude.profile import SignatureProfile
from datetime import datetime
from oscrypto import asymmetric
from oscrypto.errors import SignatureError
from xattr import getxattr, setxattr
from .utils import AuthorityHandler
from .utils.firewall import whitelist_subnets, whitelist_content_types, \
    login_required, login_optional, authorize_admin

logger = logging.getLogger(__name__)

"""
openssl genrsa -out test.key 1024
openssl req -new -sha256 -key test.key -out test.csr -subj "/CN=test"
curl -f -L -H "Content-type: application/pkcs10" --data-binary @test.csr \
  http://ca.example.lan/api/request/?wait=yes
"""

class RequestListResource(AuthorityHandler):
    @login_optional
    @whitelist_subnets(config.REQUEST_SUBNETS)
    @whitelist_content_types("application/pkcs10")
    def on_post(self, req, resp):
        """
        Validate and parse certificate signing request, the RESTful way
        """
        reasons = []
        body = req.stream.read(req.content_length)

        try:
            header, _, der_bytes = pem.unarmor(body)
            csr = CertificationRequest.load(der_bytes)
        except ValueError:
            logger.info("Malformed certificate signing request submission from %s blocked", req.context.get("remote_addr"))
            raise falcon.HTTPBadRequest(
                "Bad request",
                "Malformed certificate signing request")
        else:
            req_public_key = asymmetric.load_public_key(csr["certification_request_info"]["subject_pk_info"])
            if self.authority.public_key.algorithm != req_public_key.algorithm:
                logger.info("Attempt to submit %s based request from %s blocked, only %s allowed" % (
                    req_public_key.algorithm.upper(),
                    req.context.get("remote_addr"),
                    self.authority.public_key.algorithm.upper()))
                raise falcon.HTTPBadRequest(
                    "Bad request",
                    "Incompatible asymmetric key algorithms")

        common_name = csr["certification_request_info"]["subject"].native["common_name"]

        """
        Determine whether autosign is allowed to overwrite already issued
        certificates automatically
        """

        overwrite_allowed = False
        for subnet in config.OVERWRITE_SUBNETS:
            if req.context.get("remote_addr") in subnet:
                overwrite_allowed = True
                break


        """
        Handle domain computer automatic enrollment
        """
        machine = req.context.get("machine")
        if machine:
            reasons.append("machine enrollment not allowed from %s" % req.context.get("remote_addr"))
            for subnet in config.MACHINE_ENROLLMENT_SUBNETS:
                if req.context.get("remote_addr") in subnet:
                    if common_name != machine:
                        raise falcon.HTTPBadRequest(
                            "Bad request",
                            "Common name %s differs from Kerberos credential %s!" % (common_name, machine))

                    # Automatic enroll with Kerberos machine cerdentials
                    resp.set_header("Content-Type", "application/x-pem-file")
                    cert, resp.body = self.authority._sign(csr, body,
                        profile=config.PROFILES["rw"], overwrite=overwrite_allowed)
                    logger.info("Automatically enrolled Kerberos authenticated machine %s from %s",
                        machine, req.context.get("remote_addr"))
                    return


        """
        Attempt to renew certificate using currently valid key pair
        """
        try:
            path, buf, cert, signed, expires = self.authority.get_signed(common_name)
        except EnvironmentError:
            pass # No currently valid certificate for this common name
        else:
            cert_pk = cert["tbs_certificate"]["subject_public_key_info"].native
            csr_pk = csr["certification_request_info"]["subject_pk_info"].native

            # Same public key
            if cert_pk == csr_pk:
                buf = req.get_header("X-SSL-CERT")
                if buf:
                    # Used mutually authenticated TLS handshake, assume renewal
                    header, _, der_bytes = pem.unarmor(buf.replace("\t", "\n").replace("\n\n", "\n").encode("ascii"))
                    handshake_cert = x509.Certificate.load(der_bytes)
                    if handshake_cert.native == cert.native:
                        for subnet in config.RENEWAL_SUBNETS:
                            if req.context.get("remote_addr") in subnet:
                                resp.set_header("Content-Type", "application/x-x509-user-cert")
                                setxattr(path, "user.revocation.reason", "superseded")
                                _, resp.body = self.authority._sign(csr, body, overwrite=True,
                                    profile=SignatureProfile.from_cert(cert))
                                logger.info("Renewing certificate for %s as %s is whitelisted", common_name, req.context.get("remote_addr"))
                                return
                    reasons.append("renewal failed")
                else:
                    # No renewal requested, redirect to signed API call
                    resp.status = falcon.HTTP_SEE_OTHER
                    resp.location = os.path.join(os.path.dirname(req.relative_uri), "signed", common_name)
                    return


        """
        Process automatic signing if the IP address is whitelisted,
        autosigning was requested and certificate can be automatically signed
        """

        if req.get_param_as_bool("autosign"):
            for subnet in config.AUTOSIGN_SUBNETS:
                if req.context.get("remote_addr") in subnet:
                    try:
                        resp.set_header("Content-Type", "application/x-pem-file")
                        _, resp.body = self.authority._sign(csr, body,
                            overwrite=overwrite_allowed, profile=config.PROFILES["rw"])
                        logger.info("Autosigned %s as %s is whitelisted", common_name, req.context.get("remote_addr"))
                        return
                    except EnvironmentError:
                        logger.info("Autosign for %s from %s failed, signed certificate already exists",
                            common_name, req.context.get("remote_addr"))
                        reasons.append("autosign failed, signed certificate already exists")
                    break
            else:
                reasons.append("autosign failed, IP address not whitelisted")
        else:
            reasons.append("autosign not requested")

        # Attempt to save the request otherwise
        try:
            request_path, _, _ = self.authority.store_request(body,
                address=str(req.context.get("remote_addr")))
        except errors.RequestExists:
            reasons.append("same request already uploaded exists")
            # We should still redirect client to long poll URL below
        except errors.DuplicateCommonNameError:
            # TODO: Certificate renewal
            logger.warning("rejected signing request with overlapping common name from %s",
                req.context.get("remote_addr"))
            raise falcon.HTTPConflict(
                "CSR with such CN already exists",
                "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")
        else:
            push.publish("request-submitted", common_name)

        # Wait the certificate to be signed if waiting is requested
        logger.info("Stored signing request %s from %s, reasons: %s", common_name, req.context.get("remote_addr"), reasons)

        if req.get_param("wait"):
            # Redirect to nginx pub/sub
            url = config.LONG_POLL_SUBSCRIBE % hashlib.sha256(body).hexdigest()
            click.echo("Redirecting to: %s"  % url)
            resp.status = falcon.HTTP_SEE_OTHER
            resp.set_header("Location", url)
            logger.debug("Redirecting signing request from %s to %s, reasons: %s", req.context.get("remote_addr"), url, ", ".join(reasons))
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202
            resp.body = ". ".join(reasons)
            if req.client_accepts("application/json"):
                resp.body = json.dumps({"title":"Accepted", "description":resp.body},
                    cls=MyEncoder)


class RequestDetailResource(AuthorityHandler):
    def on_get(self, req, resp, cn):
        """
        Fetch certificate signing request as PEM
        """

        try:
            path, buf, _, submitted = self.authority.get_request(cn)
        except errors.RequestDoesNotExist:
            logger.warning("Failed to serve non-existant request %s to %s",
                cn, req.context.get("remote_addr"))
            raise falcon.HTTPNotFound()

        resp.set_header("Content-Type", "application/pkcs10")
        logger.debug("Signing request %s was downloaded by %s",
            cn, req.context.get("remote_addr"))

        preferred_type = req.client_prefers(("application/json", "application/x-pem-file"))

        if preferred_type == "application/x-pem-file":
            # For certidude client, curl scripts etc
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.pem" % cn))
            resp.body = buf
        elif preferred_type == "application/json":
            # For web interface events
            resp.set_header("Content-Type", "application/json")
            resp.set_header("Content-Disposition", ("attachment; filename=%s.json" % cn))
            resp.body = json.dumps(dict(
                submitted = submitted,
                common_name = cn,
                address = getxattr(path, "user.request.address").decode("ascii"), # TODO: move to authority.py
                md5sum = hashlib.md5(buf).hexdigest(),
                sha1sum = hashlib.sha1(buf).hexdigest(),
                sha256sum = hashlib.sha256(buf).hexdigest(),
                sha512sum = hashlib.sha512(buf).hexdigest()), cls=MyEncoder)
        else:
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json or application/x-pem-file")


    @csrf_protection
    @login_required
    @authorize_admin
    def on_post(self, req, resp, cn):
        """
        Sign a certificate signing request
        """
        try:
            cert, buf = self.authority.sign(cn,
                profile=config.PROFILES[req.get_param("profile", default="rw")],
                overwrite=True,
                signer=req.context.get("user").name)
            # Mailing and long poll publishing implemented in the function above
        except EnvironmentError: # no such CSR
            raise falcon.HTTPNotFound()

        resp.body = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = os.path.join(req.relative_uri, "..", "..", "signed", cn)
        logger.info("Signing request %s signed by %s from %s", cn,
            req.context.get("user"), req.context.get("remote_addr"))

    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        try:
            self.authority.delete_request(cn)
            # Logging implemented in the function above
        except errors.RequestDoesNotExist as e:
            resp.body = "No certificate signing request for %s found" % cn
            logger.warning("User %s failed to delete signing request %s from %s, reason: %s",
                req.context["user"], cn, req.context.get("remote_addr"), e)
            raise falcon.HTTPNotFound()
