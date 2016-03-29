
import falcon
import logging
from certidude import constants
from certidude.authority import export_crl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

logger = logging.getLogger("api")

class RevocationListResource(object):
    def on_get(self, req, resp):
        logger.debug(u"Revocation list requested by %s", req.context.get("remote_addr"))
        buf = export_crl()

        # Primarily offer DER encoded CRL as per RFC5280
        # This is also what StrongSwan expects
        if req.client_accepts("application/x-pkcs7-crl"):
            resp.set_header("Content-Type", "application/x-pkcs7-crl")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s.crl" % constants.HOSTNAME).encode("ascii"))
            # Convert PEM to DER
            resp.body = x509.load_pem_x509_crl(buf, default_backend()).public_bytes(Encoding.DER)
        elif req.client_accepts("application/x-pem-file"):
            resp.set_header("Content-Type", "application/x-pem-file")
            resp.append_header(
                "Content-Disposition",
                ("attachment; filename=%s-crl.pem" % constants.HOSTNAME).encode("ascii"))
            resp.body = buf
        else:
            raise falcon.HTTPUnsupportedMediaType(
                "Client did not accept application/x-pkcs7-crl or application/x-pem-file")
