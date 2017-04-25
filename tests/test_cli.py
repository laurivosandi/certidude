import os
import requests
from falcon import testing
from click.testing import CliRunner
from certidude.cli import entry_point as cli
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import pytest
from xattr import setxattr

# pkill py && rm -Rfv ~/.certidude && TRAVIS=1 py.test tests

runner = CliRunner()

@pytest.fixture(scope='module')
def client():
    from certidude.api import certidude_app
    return testing.TestClient(certidude_app())

def generate_csr():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend())
    csr = x509.CertificateSigningRequestBuilder(
        ).subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"test")]))
    buf = csr.sign(key, hashes.SHA256(), default_backend()
        ).public_bytes(serialization.Encoding.PEM)
    return buf

def test_cli_setup_authority():
    result = runner.invoke(cli, ['setup', 'authority'])
    assert not result.exception

    from certidude import const, config, authority
    assert authority.ca_cert.serial_number >= 0x100000000000000000000000000000000000000
    assert authority.ca_cert.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert authority.ca_cert.not_valid_before < datetime.now()
    assert authority.ca_cert.not_valid_after > datetime.now() + timedelta(days=7000)

    # Try starting up forked server
    result = runner.invoke(cli, ['serve', '-f', '-p', '8080'])
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
    buf = generate_csr()

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
        body=generate_csr(),
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 409 # duplicate cn, different keypair

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

    path, _, _ = authority.get_signed("test2")
    setxattr(path, "user.lease.address", b"127.0.0.1")

    r = client().simulate_get("/api/signed/test2/attr/")
    assert r.status_code == 200

    # Tags should not be visible anonymously
    r = client().simulate_get("/api/signed/test2/tag/")
    assert r.status_code == 401

    # Revoke all valid ones
    result = runner.invoke(cli, ['revoke', 'test2'])
    assert not result.exception

    result = runner.invoke(cli, ['revoke', 'test3'])
    assert not result.exception



