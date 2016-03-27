from click.testing import CliRunner
from certidude.cli import entry_point as cli

runner = CliRunner()

def test_ca_config():
    # Authority setup
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['setup', 'authority'])
        assert not result.exception

        from certidude import authority
        assert authority.certificate.serial_number == '0000000000000000000000000000000000000001'
        # TODO: Figure out a way to properly test cert.signed, cert.expires, cert.digest, etc
