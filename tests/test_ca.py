from click.testing import CliRunner
from certidude.cli import entry_point as cli


from certidude.wrappers import CertificateAuthorityConfig

runner = CliRunner()

def test_ca_config():
    # Authority setup
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['setup', 'authority', 'xca'])
        assert not result.exception

        # Load CA
        conf = CertificateAuthorityConfig('./xca/openssl.cnf.example')

        assert conf.ca_list == ['xca']

        ca = conf.instantiate_authority('xca')

        cert = ca.certificate

        assert cert.serial_number == '0000000000000000000000000000000000000001'
        # TODO: Figure out a way to properly test cert.signed, cert.expires, cert.digest, etc
