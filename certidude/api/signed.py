
import falcon
from certidude import authority
from certidude.auth import login_required, authorize_admin
from certidude.decorators import serialize

class SignedCertificateListResource(object):
    @serialize
    @authorize_admin
    def on_get(self, req, resp):
        for j in authority.list_signed():
            yield omit(
                key_type=j.key_type,
                key_length=j.key_length,
                identity=j.identity,
                cn=j.common_name,
                c=j.country_code,
                st=j.state_or_county,
                l=j.city,
                o=j.organization,
                ou=j.organizational_unit,
                fingerprint=j.fingerprint())


class SignedCertificateDetailResource(object):
    @serialize
    def on_get(self, req, resp, cn):
        try:
            return authority.get_signed(cn)
        except FileNotFoundError:
            resp.body = "No certificate CN=%s found" % cn
            raise falcon.HTTPNotFound()

    @login_required
    @authorize_admin
    def on_delete(self, req, resp, cn):
        authority.revoke_certificate(cn)

