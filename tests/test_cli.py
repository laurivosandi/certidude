import os
import requests
from click.testing import CliRunner
from certidude.cli import entry_point as cli
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import thread
from xattr import setxattr

runner = CliRunner()

def test_cli_setup_authority():
    result = runner.invoke(cli, ['setup', 'authority'])
    assert not result.exception
    from certidude import const, config

    from certidude import authority
    assert authority.ca_cert.serial_number >= 0x100000000000000000000000000000000000000
    assert authority.ca_cert.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert authority.ca_cert.not_valid_before < datetime.now()
    assert authority.ca_cert.not_valid_after > datetime.now() + timedelta(days=7000)

    thread.start_new_thread(runner.invoke, (cli, ['serve', '-p', '8080']))

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

    csr = x509.CertificateSigningRequestBuilder(
        ).subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"test")]))

    authority.store_request(
        csr.sign(key, hashes.SHA256(), default_backend()).public_bytes(serialization.Encoding.PEM))

    # Check that we can retrieve empty CRL
    r = requests.get("http://localhost:8080/api/revoked")
    assert r.status_code == 200

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


    # Test CA certificate fetch
    r = requests.get("http://localhost:8080/api/certificate")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-x509-ca-cert"


    # Test signed certificate API call
    r = requests.get("http://localhost:8080/api/signed/test2")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pem-file"

    r = requests.get("http://localhost:8080/api/signed/test2", headers={"Accept":"application/json"})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/json"


    # Test revocations API call
    r = requests.get("http://localhost:8080/api/revoked")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pkcs7-crl"

    r = requests.get("http://localhost:8080/api/revoked",
        headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-pem-file"

    # Test attribute fetching API call
    r = requests.get("http://localhost:8080/api/signed/test2/attr/")
    assert r.status_code == 403

    path, _, _ = authority.get_signed("test2")
    setxattr(path, "user.lease.address", b"127.0.0.1")

    r = requests.get("http://localhost:8080/api/signed/test2/attr/")
    assert r.status_code == 200

    # Tags should not be visible anonymously
    r = requests.get("http://localhost:8080/api/signed/test2/tag/")
    assert r.status_code == 401


    # Revoke all valid ones
    result = runner.invoke(cli, ['revoke', 'test2'])
    assert not result.exception

    result = runner.invoke(cli, ['revoke', 'test3'])
    assert not result.exception
