
from certidude.authority import export_crl

class RevocationListResource(object):
    def on_get(self, req, resp):
        resp.set_header("Content-Type", "application/x-pkcs7-crl")
        resp.append_header("Content-Disposition", "attachment; filename=ca.crl")
        resp.body = export_crl()

