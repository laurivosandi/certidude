import os
from click.testing import CliRunner
from certidude.cli import entry_point as cli
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

runner = CliRunner()

def test_cli_setup_authority():
    result = runner.invoke(cli, ['setup', 'authority'])
    assert not result.exception
    from certidude import const, config

    from certidude import authority
    assert authority.ca_cert.serial_number == 1
    assert authority.ca_cert.not_valid_before < datetime.now()
    assert authority.ca_cert.not_valid_after > datetime.now() + timedelta(days=7000)

    result = runner.invoke(cli, ['serve', '-f', '-p', '8080'])
    assert not result.exception


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

    result = runner.invoke(cli, ['sign', 'test', '-o'])
    assert not result.exception

    result = runner.invoke(cli, ['revoke', 'test'])
    assert not result.exception

    authority.generate_ovpn_bundle(u"test2")
    authority.generate_pkcs12_bundle(u"test3")
