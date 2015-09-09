import os
from click.testing import CliRunner
from certidude.cli import entry_point as cli

runner = CliRunner()

def test_cli():

    # Authority setup
    # TODO: group, parent, common-name, country, state, locality
    # {authority,certificate,revocation-list}-lifetime
    # organization, organizational-unit
    # pkcs11
    # {crl-distribution,ocsp-responder}-url
    # email-address
    # inbox, outbox
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['setup', 'authority', 'ca'])

        assert not result.exception
        # Check whether required files were generated
        for f in ('ca_key.pem', 'ca_crt.pem', 'ca_crl.pem',
                  'serial', 'openssl.cnf.example'):
            assert os.path.isfile(os.path.join('ca', f))
        for d in ('requests', 'revoked', 'signed'):
            assert os.path.isdir(os.path.join('ca', d))

def test_cli_setup_authority_slug_name():
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['setup', 'authority'])
        assert result.exception

        result = runner.invoke(cli, ['setup', 'authority', '""'])
        assert result.exception
