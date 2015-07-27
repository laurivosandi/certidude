

import falcon
from certidude.wrappers import CertificateAuthorityConfig
from certidude.api import CertificateAuthorityResource, \
    RequestDetailResource, RequestListResource, \
    SignedCertificateDetailResource, SignedCertificateListResource, \
    RevocationListResource, IndexResource, ApplicationConfigurationResource, \
    CertificateStatusResource

# TODO: deduplicate routing code
# TODO: set up /run/certidude/api paths and permissions

config = CertificateAuthorityConfig("/etc/ssl/openssl.cnf")

app = falcon.API()
app.add_route("/api/{ca}/ocsp/", CertificateStatusResource(config))
app.add_route("/api/{ca}/signed/{cn}/openvpn", ApplicationConfigurationResource(config))
app.add_route("/api/{ca}/certificate/", CertificateAuthorityResource(config))
app.add_route("/api/{ca}/revoked/", RevocationListResource(config))
app.add_route("/api/{ca}/signed/{cn}/", SignedCertificateDetailResource(config))
app.add_route("/api/{ca}/signed/", SignedCertificateListResource(config))
app.add_route("/api/{ca}/request/{cn}/", RequestDetailResource(config))
app.add_route("/api/{ca}/request/", RequestListResource(config))
app.add_route("/api/{ca}/", IndexResource(config))

