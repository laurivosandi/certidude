from click.testing import CliRunner
from certidude.cli import entry_point as cli
from datetime import datetime, timedelta

runner = CliRunner()

def test_cli_setup_authority():
    # Authority setup
    # TODO: parent, common-name, country, state, locality
    # {authority,certificate,revocation-list}-lifetime
    # organization, organizational-unit
    # pkcs11
    # {crl-distribution,ocsp-responder}-url
    # email-address
    # inbox, outbox

    result = runner.invoke(cli, ['setup', 'authority'])
    assert not result.exception

    from certidude import authority
    assert authority.certificate.serial_number == '0000000000000000000000000000000000000001'
    assert authority.certificate.signed < datetime.now()
    assert authority.certificate.expires > datetime.now() + timedelta(days=7000)

        
