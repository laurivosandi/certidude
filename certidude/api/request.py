
import click
import falcon
import logging
import ipaddress
import json
import os
import hashlib
from base64 import b64decode
from certidude import config, authority, push, errors
from certidude.auth import login_required, login_optional, authorize_admin
from certidude.decorators import serialize, csrf_protection
from certidude.firewall import whitelist_subnets, whitelist_content_types
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from datetime import datetime

logger = logging.getLogger(__name__)

class RequestListResource(object):
    @login_optional
    @whitelist_subnets(config.REQUEST_SUBNETS)
    @whitelist_content_types("application/pkcs10")
    def on_post(self, req, resp):
        """
        Validate and parse certificate signing request
        """
        reasons = []
        body = req.stream.read(req.content_length)
        csr = x509.load_pem_x509_csr(body, default_backend())
        try:
            common_name, = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        except: # ValueError?
            logger.warning(u"Rejected signing request without common name from %s",
                req.context.get("remote_addr"))
            raise falcon.HTTPBadRequest(
                "Bad request",
                "No common name specified!")

        """
        Handle domain computer automatic enrollment
        """
        machine = req.context.get("machine")
        if machine:
            if config.MACHINE_ENROLLMENT_ALLOWED:
                if common_name.value != machine:
                    raise falcon.HTTPBadRequest(
                        "Bad request",
                        "Common name %s differs from Kerberos credential %s!" % (common_name.value, machine))

                # Automatic enroll with Kerberos machine cerdentials
                resp.set_header("Content-Type", "application/x-pem-file")
                cert, resp.body = authority._sign(csr, body, overwrite=True)
                logger.info(u"Automatically enrolled Kerberos authenticated machine %s from %s",
                    machine, req.context.get("remote_addr"))
                return
            else:
                reasons.append("Machine enrollment not allowed")

        """
        Attempt to renew certificate using currently valid key pair
        """
        try:
            path, buf, cert = authority.get_signed(common_name.value)
        except EnvironmentError:
            pass
        else:
            if cert.public_key().public_numbers() == csr.public_key().public_numbers():
                renewal_header = req.get_header("X-Renewal-Signature")

                if not renewal_header:
                    # No header supplied, redirect to signed API call
                    resp.status = falcon.HTTP_SEE_OTHER
                    resp.location = os.path.join(os.path.dirname(req.relative_uri), "signed", common_name.value)
                    return

                try:
                    renewal_signature = b64decode(renewal_header)
                except TypeError, ValueError:
                    logger.error(u"Renewal failed, bad signature supplied for %s", common_name.value)
                    reasons.append("Renewal failed, bad signature supplied")
                else:
                    try:
                        verifier = cert.public_key().verifier(
                            renewal_signature,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA512()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA512()
                        )
                        verifier.update(buf)
                        verifier.update(body)
                        verifier.verify()
                    except InvalidSignature:
                        logger.error(u"Renewal failed, invalid signature supplied for %s", common_name.value)
                        reasons.append("Renewal failed, invalid signature supplied")
                    else:
                        # At this point renewal signature was valid but we need to perform some extra checks
                        if datetime.utcnow() > cert.not_valid_after:
                            logger.error(u"Renewal failed, current certificate for %s has expired", common_name.value)
                            reasons.append("Renewal failed, current certificate expired")
                        elif not config.CERTIFICATE_RENEWAL_ALLOWED:
                            logger.error(u"Renewal requested for %s, but not allowed by authority settings", common_name.value)
                            reasons.append("Renewal requested, but not allowed by authority settings")
                        else:
                            resp.set_header("Content-Type", "application/x-x509-user-cert")
                            _, resp.body = authority._sign(csr, body, overwrite=True)
                            logger.info(u"Renewed certificate for %s", common_name.value)
                            return


        """
        Process automatic signing if the IP address is whitelisted,
        autosigning was requested and certificate can be automatically signed
        """
        if req.get_param_as_bool("autosign"):
            if "." not in common_name.value:
                for subnet in config.AUTOSIGN_SUBNETS:
                    if req.context.get("remote_addr") in subnet:
                        try:
                            resp.set_header("Content-Type", "application/x-pem-file")
                            _, resp.body = authority._sign(csr, body)
                            logger.info(u"Autosigned %s as %s is whitelisted", common_name.value, req.context.get("remote_addr"))
                            return
                        except EnvironmentError:
                            logger.info(u"Autosign for %s from %s failed, signed certificate already exists",
                                common_name.value, req.context.get("remote_addr"))
                            reasons.append("Autosign failed, signed certificate already exists")
                        break
                else:
                    reasons.append("Autosign failed, IP address not whitelisted")
            else:
                reasons.append("Autosign failed, only client certificates allowed to be signed automatically")

        # Attempt to save the request otherwise
        try:
            csr = authority.store_request(body.decode("ascii"))
        except errors.RequestExists:
            reasons.append("Same request already uploaded exists")
            # We should still redirect client to long poll URL below
        except errors.DuplicateCommonNameError:
            # TODO: Certificate renewal
            logger.warning(u"Rejected signing request with overlapping common name from %s",
                req.context.get("remote_addr"))
            raise falcon.HTTPConflict(
                "CSR with such CN already exists",
                "Will not overwrite existing certificate signing request, explicitly delete CSR and try again")
        else:
            push.publish("request-submitted", common_name.value)

        # Wait the certificate to be signed if waiting is requested
        logger.info(u"Signing request %s from %s stored", common_name.value, req.context.get("remote_addr"))
        if req.get_param("wait"):
            # Redirect to nginx pub/sub
            url = config.LONG_POLL_SUBSCRIBE % hashlib.sha256(body).hexdigest()
            click.echo("Redirecting to: %s"  % url)
            resp.status = falcon.HTTP_SEE_OTHER
            resp.set_header("Location", url.encode("ascii"))
            logger.debug(u"Redirecting signing request from %s to %s", req.context.get("remote_addr"), url)
        else:
            # Request was accepted, but not processed
            resp.status = falcon.HTTP_202
            resp.body = ". ".join(reasons)


class RequestDetailResource(object):
    def on_get(self, req, resp, cn):
        """
        Fetch certificate signing request as PEM
        """

        try:
            _, buf, _ = authority.get_request(cn)
        except errors.RequestDoesNotExist:
            logger.warning(u"Failed to serve non-existant request %s to %s",
                cn, req.context.get("remote_addr"))
            raise falcon.HTTPNotFound()

        resp.set_header("Content-Type", "application/pkcs10")
        logger.debug(u"Signing request %s was downloaded by %s",
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
                common_name = cn,
                server = authority.server_flags(cn),
                md5sum = hashlib.md5(buf).hexdigest(),
                sha1sum = hashlib.sha1(buf).hexdigest(),
                sha256sum = hashlib.sha256(buf).hexdigest(),
                sha512sum = hashlib.sha512(buf).hexdigest()))
        else:
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/json or application/x-pem-file")


    @csrf_protection
    @login_required
    @authorize_admin
    def on_patch(self, req, resp, cn):
        """
        Sign a certificate signing request
        """
        cert, buf = authority.sign(cn, overwrite=True)
        # Mailing and long poll publishing implemented in the function above

        resp.body = "Certificate successfully signed"
        resp.status = falcon.HTTP_201
        resp.location = os.path.join(req.relative_uri, "..", "..", "signed", cn)
        logger.info(u"Signing request %s signed by %s from %s", cn,
            req.context.get("user"), req.context.get("remote_addr"))

    @csrf_protection
    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        try:
            authority.delete_request(cn)
            # Logging implemented in the function above
        except errors.RequestDoesNotExist as e:
            resp.body = "No certificate signing request for %s found" % cn
            logger.warning(u"User %s failed to delete signing request %s from %s, reason: %s",
                req.context["user"], cn, req.context.get("remote_addr"), e)
            raise falcon.HTTPNotFound()
