import subprocess
import pwd
from click.testing import CliRunner
from datetime import datetime, timedelta
import pytest

# pkill py && rm -Rfv ~/.certidude && TRAVIS=1 py.test tests

runner = CliRunner()

@pytest.fixture(scope='module')
def client():
    from certidude.api import certidude_app
    from falcon import testing
    app = certidude_app()
    return testing.TestClient(app)

def generate_csr(cn=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend())
    csr = x509.CertificateSigningRequestBuilder()
    if cn is not None:
        csr = csr.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    buf = csr.sign(key, hashes.SHA256(), default_backend()
        ).public_bytes(serialization.Encoding.PEM)
    return buf

def test_cli_setup_authority():
    import shutil
    import os
    if os.path.exists("/run/certidude/signer.pid"):
        with open("/run/certidude/signer.pid") as fh:
            try:
                os.kill(int(fh.read()), 15)
            except OSError:
                pass
        os.unlink("/run/certidude/signer.pid")
    if os.path.exists("/run/certidude/server.pid"):
        with open("/run/certidude/server.pid") as fh:
            try:
                os.kill(int(fh.read()), 15)
            except OSError:
                pass
        os.unlink("/run/certidude/server.pid")

    if os.path.exists("/var/lib/certidude/ca.example.lan"):
        shutil.rmtree("/var/lib/certidude/ca.example.lan")
    if os.path.exists("/etc/certidude/server.conf"):
        os.unlink("/etc/certidude/server.conf")
    if os.path.exists("/etc/certidude/client.conf"):
        os.unlink("/etc/certidude/client.conf")

    # Remove OpenVPN stuff
    if os.path.exists("/etc/openvpn"):
        for filename in os.listdir("/etc/openvpn"):
            if filename.endswith(".conf"):
                os.unlink(os.path.join("/etc/openvpn", filename))
        if os.path.exists("/etc/openvpn/keys"):
            shutil.rmtree("/etc/openvpn/keys")

    from certidude.cli import entry_point as cli
    from certidude import const

    result = runner.invoke(cli, ['setup', 'authority'])
    assert not result.exception

    from certidude import config, authority
    assert authority.ca_cert.serial_number >= 0x100000000000000000000000000000000000000
    assert authority.ca_cert.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert authority.ca_cert.not_valid_before < datetime.now()
    assert authority.ca_cert.not_valid_after > datetime.now() + timedelta(days=7000)

    # Start server before any signing operations are performed
    result = runner.invoke(cli, ['serve', '-f'])
    assert not result.exception

    # Password is bot, users created by Travis
    usertoken = "Basic dXNlcmJvdDpib3Q="
    admintoken = "Basic YWRtaW5ib3Q6Ym90"

    result = runner.invoke(cli, ['users'])
    assert not result.exception

    # Check that we can retrieve empty CRL
    r = client().simulate_get("/api/revoked/")
    assert r.status_code == 200


    # Test command line interface
    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception

    # Test CA certificate fetch
    r = client().simulate_get("/api/certificate")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-x509-ca-cert"

    # Test request submission
    buf = generate_csr(cn=u"test")

    r = client().simulate_post("/api/request/", body=buf)
    assert r.status_code == 415 # wrong content type

    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # success

    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # already exists, same keypair so it's ok

    r = client().simulate_post("/api/request/",
        query_string="wait=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 303 # redirect to long poll

    r = client().simulate_post("/api/request/",
        body=generate_csr(cn=u"test"),
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 409 # duplicate cn, different keypair

    r = client().simulate_get("/api/request/test/", headers={"Accept":"application/json"})
    assert r.status_code == 200 # fetch as JSON ok
    assert r.headers.get('content-type') == "application/json"

    r = client().simulate_get("/api/request/test/", headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 200 # fetch as PEM ok
    assert r.headers.get('content-type') == "application/x-pem-file"

    r = client().simulate_get("/api/request/test/", headers={"Accept":"text/plain"})
    assert r.status_code == 415 # not available as plaintext

    r = client().simulate_get("/api/request/nonexistant/", headers={"Accept":"application/json"})
    assert r.status_code == 404 # nonexistant common names

    r = client().simulate_post("/api/request/", query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 200 # autosign successful
    assert r.headers.get('content-type') == "application/x-pem-file"

    # TODO: submit messed up CSR-s: no CN, empty CN etc

    # Test command line interface
    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception
    result = runner.invoke(cli, ['sign', 'test', '-o'])
    assert not result.exception
    result = runner.invoke(cli, ['revoke', 'test'])
    assert not result.exception
    authority.generate_ovpn_bundle(u"test2")
    authority.generate_pkcs12_bundle(u"test3")
    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception
    result = runner.invoke(cli, ['cron'])
    assert not result.exception


    # Test session API call
    r = client().simulate_get("/api/", headers={"Authorization":usertoken})
    assert r.status_code == 200

    r = client().simulate_get("/api/", headers={"Authorization":admintoken})
    assert r.status_code == 200

    r = client().simulate_get("/api/")
    assert r.status_code == 401


    # Test signed certificate API call
    r = client().simulate_get("/api/signed/nonexistant/")
    assert r.status_code == 404

    r = client().simulate_get("/api/signed/test2/")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pem-file"

    r = client().simulate_get("/api/signed/test2/", headers={"Accept":"application/json"})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/json"

    r = client().simulate_get("/api/signed/test2/", headers={"Accept":"text/plain"})
    assert r.status_code == 415

    # Test revocations API call
    r = client().simulate_get("/api/revoked/")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pkcs7-crl"

    r = client().simulate_get("/api/revoked/",
        headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pem-file"

    r = client().simulate_get("/api/revoked/",
        headers={"Accept":"text/plain"})
    assert r.status_code == 415

    r = client().simulate_get("/api/revoked/", query_string="wait=true",
        headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 303

    # Test attribute fetching API call
    r = client().simulate_get("/api/signed/test2/attr/")
    assert r.status_code == 403
    r = client().simulate_get("/api/signed/test2/lease/", headers={"Authorization":admintoken})
    assert r.status_code == 404

    # Insert lease as if VPN gateway had submitted it
    path, _, _ = authority.get_signed("test2")
    from xattr import setxattr
    setxattr(path, "user.lease.address", b"127.0.0.1")
    setxattr(path, "user.lease.last_seen", b"random")
    r = client().simulate_get("/api/signed/test2/attr/")
    assert r.status_code == 200

    # Test lease retrieval
    r = client().simulate_get("/api/signed/test2/lease/")
    assert r.status_code == 401
    r = client().simulate_get("/api/signed/test2/lease/", headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_get("/api/signed/test2/lease/", headers={"Authorization":admintoken})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/json; charset=UTF-8"


    # Tags should not be visible anonymously
    r = client().simulate_get("/api/signed/test2/tag/")
    assert r.status_code == 401
    r = client().simulate_get("/api/signed/test2/tag/", headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_get("/api/signed/test2/tag/", headers={"Authorization":admintoken})
    assert r.status_code == 200

    # Tags can be added only by admin
    r = client().simulate_post("/api/signed/test2/tag/")
    assert r.status_code == 401
    r = client().simulate_post("/api/signed/test2/tag/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_post("/api/signed/test2/tag/",
        body="key=other&value=something",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200

    # Tags can be overwritten only by admin
    r = client().simulate_put("/api/signed/test2/tag/other/")
    assert r.status_code == 401
    r = client().simulate_put("/api/signed/test2/tag/other/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_put("/api/signed/test2/tag/other/",
        body="value=else",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200

    # Tags can be deleted only by admin
    r = client().simulate_delete("/api/signed/test2/tag/else/")
    assert r.status_code == 401
    r = client().simulate_delete("/api/signed/test2/tag/else/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_delete("/api/signed/test2/tag/else/",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200


    # Test revocation
    r = client().simulate_delete("/api/signed/test2/")
    assert r.status_code == 401
    r = client().simulate_delete("/api/signed/test2/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_delete("/api/signed/test2/",
        headers={"Authorization":admintoken})
    assert r.status_code == 200
    result = runner.invoke(cli, ['revoke', 'test3'])
    assert not result.exception


    # Test static
    r = client().simulate_delete("/nonexistant.html")
    assert r.status_code == 404
    r = client().simulate_delete("/index.html")
    assert r.status_code == 200

    # Log can be read only by admin
    r = client().simulate_get("/api/log/")
    assert r.status_code == 401
    r = client().simulate_get("/api/log/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403
    r = client().simulate_get("/api/log/",
        headers={"Authorization":admintoken})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/json; charset=UTF-8"

    # Test token mech
    r = client().simulate_post("/api/token/")
    assert r.status_code == 404

    config.BUNDLE_FORMAT = "ovpn"
    config.USER_ENROLLMENT_ALLOWED = True

    r = client().simulate_post("/api/token/")
    assert r.status_code == 401 # needs auth
    r = client().simulate_post("/api/token/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403 # regular user forbidden
    r = client().simulate_post("/api/token/",
        body="user=userbot", # TODO: test nonexistant user
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200 # token generated by admin

    r2 = client().simulate_get("/api/token/",
        query_string="u=userbot&t=1493184342&c=ac9b71421d5741800c5a4905b20c1072594a2df863e60ba836464888786bf2a6",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r2.status_code == 403 # invalid checksum
    r2 = client().simulate_get("/api/token/", query_string=r.content,
        headers={"User-Agent":"Mozilla/5.0 (X11; Fedora; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"})
    assert r2.status_code == 200 # token consumed by anyone on Fedora
    assert r2.headers.get('content-type') == "application/x-openvpn"

    config.BUNDLE_FORMAT = "p12" # Switch to PKCS#12
    r2 = client().simulate_get("/api/token/", query_string=r.content)
    assert r2.status_code == 200 # token consumed by anyone on unknown device
    assert r2.headers.get('content-type') == "application/x-pkcs12"


    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn.example.lan", "ca.example.lan"])
    assert not result.exception

    result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "roadwarrior1", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception

    import os
    if not os.path.exists("/etc/openvpn/keys"):
        os.makedirs("/etc/openvpn/keys")

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    # pregen dhparam
    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception
    result = runner.invoke(cli, ['sign', 'vpn.example.lan'])
    assert not result.exception
    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception
