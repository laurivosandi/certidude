import coverage
import pwd
from asn1crypto import pem, x509
from oscrypto import asymmetric
from csrbuilder import CSRBuilder, pem_armor_csr
from asn1crypto.util import OrderedDict
from subprocess import check_output
from importlib import reload
from click.testing import CliRunner
from datetime import datetime, timedelta
from time import sleep
import json
import pytest
import shutil
import sys
import os

coverage.process_startup()

UA_FEDORA_FIREFOX = "Mozilla/5.0 (X11; Fedora; Linux x86_64) " \
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36"

smtp=None
inbox=[]

class DummySMTP(object):
    def __init__(self,address):
        self.address=address

    def login(self,username,password):
        self.username=username
        self.password=password

    def sendmail(self,from_address,to_address,fullmessage):
        global inbox
        inbox.append(fullmessage)
        return []

    def quit(self):
        self.has_quit=True

# this is the actual monkey patch (simply replacing one class with another)
import smtplib
smtplib.SMTP=DummySMTP

runner = CliRunner()

@pytest.fixture(scope='module')
def client():
    from certidude.api import certidude_app
    from falcon import testing
    app = certidude_app()
    return testing.TestClient(app)

def generate_csr(cn=None):

    public_key, private_key = asymmetric.generate_pair('ec', curve="secp384r1")
    builder = CSRBuilder({ 'common_name': cn }, public_key)
    request = builder.build(private_key)
    return pem_armor_csr(request)


def clean_client():
    assert os.getuid() == 0 and os.getgid() == 0
    files = [
        "/etc/certidude/client.conf",
        "/etc/certidude/services.conf",
        "/etc/certidude/authority/ca.example.lan/ca_cert.pem",
        "/etc/certidude/authority/ca.example.lan/client_key.pem",
        "/etc/certidude/authority/ca.example.lan/server_key.pem",
        "/etc/certidude/authority/ca.example.lan/client_req.pem",
        "/etc/certidude/authority/ca.example.lan/server_req.pem",
        "/etc/certidude/authority/ca.example.lan/client_cert.pem",
        "/etc/certidude/authority/ca.example.lan/server_cert.pem",
        "/etc/NetworkManager/system-connections/IPSec to ipsec.example.lan",
        "/etc/NetworkManager/system-connections/OpenVPN to vpn.example.lan",
    ]
    for path in files:
        if os.path.exists(path):
            os.unlink(path)

    # Remove client storage area
    if os.path.exists("/tmp/ca.example.lan"):
        for filename in os.listdir("/tmp/ca.example.lan"):
            if filename.endswith(".pem"):
                os.unlink(os.path.join("/tmp/ca.example.lan", filename))

    # Reset IPsec stuff
    with open("/etc/ipsec.conf", "w") as fh: # TODO: make compatible with Fedora
        pass
    with open("/etc/ipsec.secrets", "w") as fh: # TODO: make compatible with Fedora
        pass


def clean_server():
    # Stop Samba
    os.system("systemctl stop samba-ad-dc")

    os.umask(0o22)

    if os.path.exists("/var/lib/certidude"):
        shutil.rmtree("/var/lib/certidude")
    if os.path.exists("/run/certidude"):
        shutil.rmtree("/run/certidude")

    files = [
        "/etc/krb5.keytab",
        "/etc/samba/smb.conf",
        "/etc/certidude/server.conf",
        "/etc/certidude/builder.conf",
        "/etc/certidude/profile.conf",
        "/var/log/certidude.log",
        "/etc/cron.hourly/certidude",
        "/etc/systemd/system/certidude.service",
        "/etc/nginx/sites-available/ca.conf",
        "/etc/nginx/sites-enabled/ca.conf",
        "/etc/nginx/sites-available/certidude.conf",
        "/etc/nginx/sites-enabled/certidude.conf",
        "/etc/nginx/conf.d/tls.conf",
        "/etc/certidude/server.keytab",
        "/tmp/sscep/ca.pem",
        "/tmp/key.pem",
        "/tmp/req.pem",
        "/tmp/cert.pem",
        "/usr/bin/node",
    ]

    for filename in files:
        try:
            os.unlink(filename)
        except:
            pass

    # Remove OpenVPN stuff
    if os.path.exists("/etc/openvpn"):
        for filename in os.listdir("/etc/openvpn"):
            if filename.endswith(".conf"):
                os.unlink(os.path.join("/etc/openvpn", filename))
        if os.path.exists("/etc/openvpn/keys"):
            shutil.rmtree("/etc/openvpn/keys")

    # Remove Samba stuff
    os.system("rm -Rfv /var/lib/samba/*")
    assert not os.path.exists("/var/lib/samba/private/secrets.keytab")
    assert not os.path.exists("/etc/krb5.keytab")

    # Restore initial resolv.conf
    shutil.copyfile("/etc/resolv.conf.orig", "/etc/resolv.conf")

def assert_cleanliness():
    assert os.getuid() == 0, "Environment contaminated, UID: %d" % os.getuid()
    assert os.getgid() == 0, "Environment contaminated, GID: %d" % os.getgid()
    assert not os.environ.get("KRB5_KTNAME"), "Environment contaminated, KRB5_KTNAME=%s" % os.environ.get("KRB5_KTNAME")
    assert not os.environ.get("KRB5CCNAME"), "Environment contaminated, KRB5CCNAME=%s" % os.environ.get("KRB5CCNAME")

def test_cli_setup_authority():
    assert os.getuid() == 0, "Run tests as root in a clean VM or container"
    assert check_output(["/bin/hostname", "-f"]) == b"ca.example.lan\n", "As a safety precaution, unittests only run in a machine whose hostanme -f  is ca.example.lan"

    os.system("DEBIAN_FRONTEND=noninteractive apt-get install -qq -y git build-essential python-dev libkrb5-dev samba krb5-user")

    assert_cleanliness()

    # Mock Fedora
    for util in "/usr/bin/chcon", "/usr/bin/dnf", "/usr/bin/update-ca-trust", "/usr/sbin/dmidecode":
        with open(util, "w") as fh:
            fh.write("#!/bin/bash\n")
            fh.write("exit 0\n")
        os.chmod(util, 0o755)
    if not os.path.exists("/etc/pki/ca-trust/source/anchors/"):
        os.makedirs("/etc/pki/ca-trust/source/anchors/")

    if not os.path.exists("/bin/systemctl"):
        with open("/usr/bin/systemctl", "w") as fh:
            fh.write("#!/bin/bash\n")
            fh.write("service $2 $1\n")
        os.chmod("/usr/bin/systemctl", 0o755)

    # Back up original DNS server
    if not os.path.exists("/etc/resolv.conf.orig"):
        shutil.copyfile("/etc/resolv.conf", "/etc/resolv.conf.orig")

    clean_server()
    clean_client()

    with open("/etc/hosts", "w") as fh:
        fh.write("127.0.0.1 localhost\n")

    from certidude import const
    assert const.FQDN == "ca"
    assert const.HOSTNAME == "ca"
    assert not const.DOMAIN

    # TODO: set hostname to 'ca'
    with open("/etc/hosts", "w") as fh:
        fh.write("127.0.0.1 localhost\n")
        fh.write("127.0.1.1 ca.example.lan ca\n")
        fh.write("127.0.0.1 vpn.example.lan vpn\n")
        fh.write("127.0.0.1 www.example.lan www\n")

    with open("/etc/passwd") as fh: # TODO: Better
        buf = fh.read()
        if "adminbot" not in buf:
            os.system("useradd adminbot -G sudo -p '$1$PBkf5waA$n9EV6WJ7PS6lyGWkgeTPf1'")
        if "userbot" not in buf:
            os.system("useradd userbot -G users -p '$1$PBkf5waA$n9EV6WJ7PS6lyGWkgeTPf1' -c 'User Bot,,,'")

    reload(const)
    from certidude.cli import entry_point as cli

    assert const.FQDN == "ca.example.lan"
    assert const.HOSTNAME == "ca"
    assert const.DOMAIN == "example.lan"

    # Bootstrap authority again with:
    # - ECDSA certificates
    # - POSIX auth
    # - OCSP enabled
    # - SCEP disabled
    # - CRL enabled

    assert os.system("certidude setup authority --elliptic-curve") == 0

    assert_cleanliness()

    assert os.path.exists("/var/lib/certidude/signed/ca.example.lan.pem"), "provisioning failed"
    assert not os.path.exists("/etc/cron.hourly/certidude")

    # Make sure nginx is running
    assert os.system("nginx -t") == 0, "invalid nginx configuration"
    os.system("systemctl restart certidude")
    os.system("systemctl restart nginx")
    assert os.path.exists("/run/nginx.pid"), "nginx wasn't started up properly"

    # Make sure we generated legit CA certificate
    from certidude import config, authority, user

    # Generate garbage
    with open("/var/lib/certidude/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/requests/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/signed/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/revoked/bla", "w") as fh:
        pass

    # Start server before any signing operations are performed
    assert_cleanliness()

    import requests
    for j in range(0,10):
        r = requests.get("http://ca.example.lan/api/")
        if r.status_code != 502:
            break
        sleep(1)
    assert r.status_code == 401, "Timed out starting up the API backend"

    # TODO: check that port 8080 is listening, otherwise app probably crashed


    # Test CA certificate fetch
    r = requests.get("http://ca.example.lan/api/certificate")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-x509-ca-cert"
    header, _, certificate_der_bytes = pem.unarmor(r.text.encode("ascii"))
    cert = x509.Certificate.load(certificate_der_bytes)

    assert cert.subject.native.get("common_name") == "Certidude at ca.example.lan"
    assert cert.subject.native.get("organizational_unit_name") == "Certificate Authority"
    assert cert.serial_number >= 0x150000000000000000000000000000
    assert cert.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None) < datetime.utcnow()
    assert cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None) > datetime.utcnow() + timedelta(days=7000)
    assert cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None) < datetime.utcnow()

    extensions = cert["tbs_certificate"]["extensions"].native
    assert extensions[0] == OrderedDict([
        ('extn_id', 'basic_constraints'),
        ('critical', True),
        ('extn_value', OrderedDict([
            ('ca', True),
            ('path_len_constraint', None)]
        ))]), extensions[0]
#    assert extensions[1][0] == "key_identifier", extensions[1]

    assert extensions[2] == OrderedDict([
        ('extn_id', 'key_usage'),
        ('critical', True),
        ('extn_value', {'key_cert_sign', 'crl_sign'})]), extensions[3]
    assert len(extensions) == 3

    public_key = asymmetric.load_public_key(cert["tbs_certificate"]["subject_public_key_info"])
    assert public_key.algorithm == "ec"



    # Password is bot, users created by Travis
    usertoken = "Basic dXNlcmJvdDpib3Q="
    admintoken = "Basic YWRtaW5ib3Q6Ym90"


    result = runner.invoke(cli, ['users'])
    assert not result.exception, result.output
    assert "user;userbot;User;Bot;userbot@example.lan" in result.output
    assert "admin;adminbot;;;adminbot@example.lan" in result.output
    # TODO: assert nothing else is in the list

    # Check that we can retrieve empty CRL
    assert authority.export_crl(), "Failed to export CRL"
    r = requests.get("http://ca.example.lan/api/revoked/")
    assert r.status_code == 200, r.text

    # Test command line interface
    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception, result.output

    # Test static
    r = requests.get("http://ca.example.lan/index.html")
    assert r.status_code == 200, r.text # if this breaks certidude serve has no read access to static folder
    r = requests.get("http://ca.example.lan/nonexistant.html")
    assert r.status_code == 404, r.text
    r = requests.get("http://ca.example.lan/../nonexistant.html")
    assert r.status_code == 400, r.text

    r = client().simulate_get("/")
    assert r.status_code == 404, r.text # backend doesn't serve static

    # Test request submission
    buf = generate_csr(cn="test")

    r = client().simulate_post("/api/request/", body=buf)
    assert r.status_code == 415 # wrong content type

    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # success
    assert "Stored request " in inbox.pop(), inbox
    assert os.path.exists("/var/lib/certidude/requests/test.pem")

    # Test request deletion
    r = client().simulate_delete("/api/request/test/")
    assert r.status_code == 401, r.text
    r = client().simulate_delete("/api/request/test/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_delete("/api/request/test/",
        headers={"User-Agent":UA_FEDORA_FIREFOX, "Authorization":admintoken})
    assert r.status_code == 403, r.text # CSRF prevented
    assert os.path.exists("/var/lib/certidude/requests/test.pem")
    r = client().simulate_delete("/api/request/test/",
        headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_delete("/api/request/nonexistant/",
        headers={"Authorization":admintoken})
    assert r.status_code == 404, r.text

    # Test request submission corner cases
    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # success
    assert "Stored request " in inbox.pop(), inbox

    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # already exists, same keypair so it's ok
    assert not inbox

    r = client().simulate_post("/api/request/",
        query_string="wait=true",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 303 # redirect to long poll
    assert not inbox

    r = client().simulate_post("/api/request/",
        body=generate_csr(cn="test"),
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 409 # duplicate cn, different keypair
    assert not inbox

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

    # TODO: submit messed up CSR-s: no CN, empty CN etc

    # Test command line interface
    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception, result.output

    # Test sign API call
    r = client().simulate_post("/api/request/test/")
    assert r.status_code == 401, r.text
    r = client().simulate_post("/api/request/test/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_post("/api/request/test/",
        headers={"Authorization":admintoken})
    assert r.status_code == 201, r.text
    assert "Signed " in inbox.pop(), inbox

    # Test autosign
    buf = generate_csr(cn="test2")
    r = client().simulate_post("/api/request/",
        query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 200 # autosign successful
    assert r.headers.get('content-type') == "application/x-pem-file"
    assert "Signed " in inbox.pop(), inbox
    assert not inbox

    r = client().simulate_post("/api/request/",
        query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 303 # already signed, redirect to signed certificate
    assert not inbox

    buf = generate_csr(cn="test2")
    r = client().simulate_post("/api/request/",
        query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # duplicate CN, request stored
    assert "Stored request " in inbox.pop(), inbox
    assert not inbox

    # Test signed certificate API call
    r = client().simulate_get("/api/signed/nonexistant/")
    assert r.status_code == 404, r.text

    r = client().simulate_get("/api/signed/test/")
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/x-pem-file"

    header, _, certificate_der_bytes = pem.unarmor(r.text.encode("ascii"))
    cert = x509.Certificate.load(certificate_der_bytes)
    assert cert.subject.native.get("common_name") == "test"
    assert cert.subject.native.get("organizational_unit_name") == "Roadwarrior"
    assert cert.serial_number >= 0x150000000000000000000000000000
    assert cert.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None) < datetime.utcnow()
    assert cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None) > datetime.utcnow() + timedelta(days=100)
    assert cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None) < datetime.utcnow()

    public_key = asymmetric.load_public_key(cert["tbs_certificate"]["subject_public_key_info"])
    assert public_key.algorithm == "ec"
    """
    extensions = cert["tbs_certificate"]["extensions"].native
    assert extensions[0] == OrderedDict([
        ('extn_id', 'basic_constraints'),
        ('critical', True),
        ('extn_value', OrderedDict([
            ('ca', True),
            ('path_len_constraint', None)]
        ))]), extensions[0]
#    assert extensions[1][0] == "key_identifier", extensions[1]

    assert extensions[2] == OrderedDict([
        ('extn_id', 'key_usage'),
        ('critical', True),
        ('extn_value', {'key_cert_sign', 'crl_sign'})]), extensions[3]
    assert len(extensions) == 3

    """


    r = client().simulate_get("/api/signed/test/", headers={"Accept":"application/json"})
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/json"

    r = client().simulate_get("/api/signed/test/", headers={"Accept":"text/plain"})
    assert r.status_code == 415, r.text

    # Test revocations API call
    r = client().simulate_get("/api/revoked/",
        headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/x-pem-file"

    r = client().simulate_get("/api/revoked/")
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/x-pkcs7-crl"

    r = client().simulate_get("/api/revoked/",
        headers={"Accept":"text/plain"})
    assert r.status_code == 415, r.text

    # Test attribute fetching API call
    r = client().simulate_get("/api/signed/test/attr/")
    assert r.status_code == 401, r.text
    r = client().simulate_get("/api/signed/test/attr/", headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_get("/api/signed/test/attr/", headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_get("/api/signed/nonexistant/attr/", headers={"Authorization":admintoken})
    assert r.status_code == 404, r.text

    # Tags should not be visible anonymously
    r = client().simulate_get("/api/signed/test/tag/")
    assert r.status_code == 401, r.text
    r = client().simulate_get("/api/signed/test/tag/", headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_get("/api/signed/test/tag/", headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text

    # Tags can be added only by admin
    r = client().simulate_post("/api/signed/test/tag/")
    assert r.status_code == 401, r.text
    r = client().simulate_post("/api/signed/test/tag/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_post("/api/signed/test/tag/",
        body="key=other&value=something",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_post("/api/signed/test/tag/",
        body="key=location&value=Tallinn",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text

    # Tags can be overwritten only by admin
    r = client().simulate_put("/api/signed/test/tag/something/")
    assert r.status_code == 401, r.text
    r = client().simulate_put("/api/signed/test/tag/something/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_put("/api/signed/test/tag/something/",
        body="value=else",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_put("/api/signed/test/tag/location=Tallinn/",
        body="value=Tartu",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_get("/api/signed/test/tag/", headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    # TODO: assert set(json.loads(r.text)) == set([{"key": "location", "id": "location=Tartu", "value": "Tartu"}, {"key": "other", "id": "else", "value": "else"}]), r.text


    # Test scripting
    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 403, r.text # script not authorized
    r = client().simulate_get("/api/signed/nonexistant/script/")
    assert r.status_code == 404, r.text # cert not found

    # Insert lease
    r = client().simulate_get("/api/signed/test/lease/", headers={"Authorization":admintoken})
    assert r.status_code == 404, r.text
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=127.0.0.1&outer_address=8.8.8.8")
    assert r.status_code == 403, r.text # lease update forbidden without cert

    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=127.0.0.1&outer_address=8.8.8.8",
        headers={"X-SSL-CERT":open("/var/lib/certidude/signed/ca.example.lan.pem").read() })
    assert r.status_code == 200, r.text # lease update ok

    # Attempt to fetch and execute default.sh script
    from xattr import listxattr, getxattr
    assert not [j for j in listxattr("/var/lib/certidude/signed/test.pem") if j.startswith(b"user.machine.")]
    #os.system("curl http://ca.example.lan/api/signed/test/script | bash")
    r = client().simulate_post("/api/signed/test/attr", body="cpu=i5&mem=512M&dist=Ubunt",
        headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200, r.text
    assert getxattr("/var/lib/certidude/signed/test.pem", "user.machine.cpu") == b"i5"
    assert getxattr("/var/lib/certidude/signed/test.pem", "user.machine.mem") == b"512M"
    assert getxattr("/var/lib/certidude/signed/test.pem", "user.machine.dist") == b"Ubunt"

    # Test tagging integration in scripting framework
    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 200, r.text # script render ok
    assert "curl https://ca.example.lan:8443/api/signed/test/attr " in r.text, r.text
    assert "Tartu" in r.text, r.text

    r = client().simulate_post("/api/signed/test/tag/",
        body="key=script&value=openwrt.sh",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text

    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 200, r.text # script render ok
    assert "uci set " in r.text, r.text

    # Test lease retrieval
    r = client().simulate_get("/api/signed/test/lease/")
    assert r.status_code == 401, r.text
    r = client().simulate_get("/api/signed/test/lease/", headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_get("/api/signed/test/lease/", headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/json; charset=UTF-8"

    # Tags can be deleted only by admin
    r = client().simulate_delete("/api/signed/test/tag/else/")
    assert r.status_code == 401, r.text
    r = client().simulate_delete("/api/signed/test/tag/else/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_delete("/api/signed/test/tag/else/",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_delete("/api/signed/test/tag/location=Tartu/",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_delete("/api/signed/test/tag/script=openwrt.sh/",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200, r.text
    r = client().simulate_get("/api/signed/test/tag/", headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    assert r.text == "[]", r.text

    # Test script without tags
    r = requests.get("http://ca.example.lan/api/signed/test/script/")
    assert r.status_code == 200, r.text # script render ok
    assert "# No tags" in r.text, r.text

    # Test lease update
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=127.0.0.1&outer_address=8.8.8.8&serial=0",
        headers={"X-SSL-CERT":open("/var/lib/certidude/signed/ca.example.lan.pem").read() })
    assert r.status_code == 403, r.text # invalid serial number supplied
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=1.2.3.4&outer_address=8.8.8.8",
        headers={"X-SSL-CERT":open("/var/lib/certidude/signed/ca.example.lan.pem").read() })
    assert r.status_code == 200, r.text # lease update ok


    # Test revocation
    r = client().simulate_delete("/api/signed/test/")
    assert r.status_code == 401, r.text
    r = client().simulate_delete("/api/signed/test/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_delete("/api/signed/test/",
        headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    assert "Revoked " in inbox.pop(), inbox

    # Log can be read only by admin
    r = requests.get("http://ca.example.lan/api/log/?limit=100")
    assert r.status_code == 401, r.text
    r = requests.get("http://ca.example.lan/api/log/?limit=100",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = requests.get("http://ca.example.lan/api/log/?limit=100",
        headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/json; charset=UTF-8"

    # Test session API call
    r = client().simulate_get("/api/")
    assert r.status_code == 401
    assert "Please authenticate" in r.text

    r = client().simulate_get("/api/", headers={"Accept":"text/plain", "Authorization":admintoken})
    assert r.status_code == 415 # invalid media type

    r = client().simulate_get("/api/", headers={"Authorization":usertoken})
    assert r.status_code == 403 # regular users have no access

    r = client().simulate_get("/api/", headers={"Authorization":admintoken})
    assert r.status_code == 200
    assert r.headers.get('content-type').startswith("application/json")
    assert "/ev/sub/" in r.text, r.text
    assert r.json, r.text
    assert r.json.get("authority"), r.text
    ev_url = r.json.get("authority").get("events")
    assert ev_url, r.text
    if ev_url.startswith("/"): # Expand URL
        ev_url = "http://ca.example.lan" + ev_url
    assert ev_url.startswith("http://ca.example.lan/ev/sub/")


    # TODO: issue token, should fail because there are no routers

    #############
    ### nginx ###
    #############

    # In this case nginx is set up as web server with TLS certificates
    # generated by certidude.

    clean_client()

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www", "ca.example.lan"])
    assert result.exception

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www.example.lan", "ca.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("autosign = false\n")

    assert not os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")
    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "(autosign not requested)" in result.output, result.output
    assert not os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")

    child_pid = os.fork()
    if not child_pid:
        result = runner.invoke(cli, ["sign", "www.example.lan", "--profile", "srv"])
        assert not result.exception, result.output
        assert "Publishing request-signed event 'www.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")

    result = runner.invoke(cli, ["enroll", "--skip-self", "--renew", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Renewing using current keypair" in result.output, result.output

    # Test nginx setup
    assert os.system("nginx -t") == 0, "Generated nginx config was invalid"


    ###############
    ### OpenVPN ###
    ###############

    # First OpenVPN server is set up

    clean_client()
    assert not os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")

    if not os.path.exists("/etc/openvpn/keys"):
        os.makedirs("/etc/openvpn/keys")

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn", "ca.example.lan"])
    assert result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn.example.lan", "ca.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("autosign = false\n")

    assert not os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert "(autosign not requested)" in result.output, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert not os.path.exists("/var/lib/certidude/signed/vpn.example.lan.pem")

    child_pid = os.fork()
    if not child_pid:
        assert not os.path.exists("/var/lib/certidude/signed/vpn.example.lan.pem")
        result = runner.invoke(cli, ["sign", "vpn.example.lan", "--profile", "srv"])
        assert not result.exception, result.output
        assert "overwrit" not in result.output, result.output
        assert "Publishing request-signed event 'vpn.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/certidude/authority//ca.example.lan/server_cert.pem")
    assert os.path.exists("/etc/openvpn/site-to-client.conf")

    # Secondly OpenVPN client is set up

    os.unlink("/etc/certidude/client.conf")
    os.unlink("/etc/certidude/services.conf")

    result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "roadwarrior1", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "roadwarrior1", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/openvpn/client-to-site.conf")

    # TODO: Check that tunnel interfaces came up, perhaps try to ping?
    # TODO: assert key, req, cert paths were included correctly in OpenVPN config

    clean_client()

    result = runner.invoke(cli, ['setup', 'openvpn', 'networkmanager', "-cn", "roadwarrior3", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/NetworkManager/system-connections/OpenVPN to vpn.example.lan")


    # Issue token, needs legit router ^
    os.system("certidude token issue userbot")

    ########################
    # Test image builder ###
    ########################

    r = client().simulate_get("/api/build/ar150-mfp-sysupgrade/mfp-gl-ar150-squashfs-sysupgrade.bin")
    assert r.status_code == 401, r.text
    r = client().simulate_get("/api/build/ar150-mfp-sysupgrade/mfp-gl-ar150-squashfs-sysupgrade.bin",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_get("/api/build/ar150-mfp-sysupgrade/mfp-gl-ar150-squashfs-sysupgrade.bin",
        headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text


    #######################
    ### Token mechanism ###
    #######################

    r = client().simulate_post("/api/token/",
        body="username=userbot",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r.status_code == 200

    # TODO: check consume


    #################################
    ### Subscribe to event source ###
    #################################

    ev_pid = os.fork()
    if not ev_pid:
        r = requests.get(ev_url, headers={"Accept": "text/event-stream"}, stream=True)
        assert r.status_code == 200, r.text
        i = r.iter_lines(decode_unicode=True)
        assert i.__next__() == ": hi"
        assert not i.__next__()

        # IPSec gateway below
        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        """
        assert i.__next__().startswith('data: {"message": "Served CA certificate ')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: request-submitted", "%s; %s" % (i.__next__(), i.__next__())
        assert i.__next__().startswith("id:")
        assert i.__next__() == "data: ipsec.example.lan"
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Stored signing request ipsec.example.lan ')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Stored signing request ipsec.example.lan ')
        assert not i.__next__()

        assert i.__next__() == "event: request-signed"
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: ipsec.example.lan')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Served certificate ipsec.example.lan')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Served certificate ipsec.example.lan')
        assert not i.__next__()

        # IPsec client as service enroll
        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: request-signed", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: roadwarrior2')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Autosigned roadwarrior2')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Autosigned roadwarrior2')
        assert not i.__next__()


        # IPSec client using Networkmanger enroll
        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Served CA certificate ')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.__next__()

        assert i.__next__() == "event: request-signed", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: roadwarrior4')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__()
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Autosigned roadwarrior4')
        assert not i.__next__()

        assert i.__next__() == "event: log-entry", i.__next__() # FIXME
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: {"message": "Autosigned roadwarrior4')
        assert not i.__next__()


        # Revoke
        assert i.__next__() == "event: certificate-revoked", i.__next__() # why?!
        assert i.__next__().startswith("id:")
        assert i.__next__().startswith('data: roadwarrior4')
        assert not i.__next__()
        """
        return


    #############
    ### IPSec ###
    #############

    # Setup gateway

    clean_client()
    assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec", "ca.example.lan"])
    assert result.exception, result.output # FQDN required
    assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec.example.lan", "ca.example.lan"])
    assert not result.exception, result.output
    assert open("/etc/ipsec.secrets").read() == ": RSA /etc/certidude/authority/ca.example.lan/server_key.pem\n"
    assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate
    assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("autosign = false\n")
        fh.write("system wide = yes\n")

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert "(autosign not requested)" in result.output, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")

    child_pid = os.fork()
    if not child_pid:
        assert not os.path.exists("/var/lib/certidude/signed/ipsec.example.lan.pem")
        result = runner.invoke(cli, ["sign", "ipsec.example.lan", "--profile", "srv"])
        assert not result.exception, result.output
        assert "overwrit" not in result.output, result.output
        assert "Publishing request-signed event 'ipsec.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output

    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/certidude/authority/ca.example.lan/server_cert.pem")

    # IPSec client as service

    os.unlink("/etc/certidude/client.conf")
    os.unlink("/etc/certidude/services.conf")

    result = runner.invoke(cli, ['setup', 'strongswan', 'client', "-cn", "roadwarrior2", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'strongswan', 'client', "-cn", "roadwarrior2", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output

    assert "Writing certificate to:" in result.output, result.output

    # IPSec using NetworkManager

    clean_client()

    result = runner.invoke(cli, ['setup', 'strongswan', 'networkmanager', "-cn", "roadwarrior4", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/NetworkManager/system-connections/IPSec to ipsec.example.lan")

    ######################################
    ### Test revocation on client side ###
    ######################################

    # First revoke on server side
    child_pid = os.fork()
    if not child_pid:
        result = runner.invoke(cli, ['revoke', 'roadwarrior4'])
        assert not result.exception, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    # Make sure check is ran on the client side
    result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    #assert "Certificate has been revoked, wiping keys and certificates" in result.output, result.output
    #assert "Writing certificate to:" in result.output, result.output

    #########################################################
    ### Test that legacy features are disabled by default ###
    #########################################################

    r = requests.get("http://ca.example.lan/api/scep/")
    assert r.status_code == 404
    r = requests.post("http://ca.example.lan/api/scep/")
    assert r.status_code == 404


    #################
    ### Test OCSP ###
    #################

    r = requests.get("http://ca.example.lan/api/ocsp/")
    assert r.status_code == 400
    r = requests.post("http://ca.example.lan/api/ocsp/")
    assert r.status_code == 400


    assert os.system("openssl ocsp -issuer /var/lib/certidude/ca_cert.pem -CAfile /var/lib/certidude/ca_cert.pem -cert /var/lib/certidude/signed/roadwarrior2.pem -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp1.log") == 0
    assert os.system("openssl ocsp -issuer /var/lib/certidude/ca_cert.pem -CAfile /var/lib/certidude/ca_cert.pem -cert /var/lib/certidude/ca_cert.pem -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp2.log") == 0

    for filename in os.listdir("/var/lib/certidude/revoked"):
        if not filename.endswith(".pem"):
            continue
        assert os.system("openssl ocsp -issuer /var/lib/certidude/ca_cert.pem -CAfile /var/lib/certidude/ca_cert.pem -cert /var/lib/certidude/revoked/%s -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp3.log" % filename) == 0
        break

    with open("/tmp/ocsp1.log") as fh:
        buf = fh.read()
        assert ": good" in buf, buf
    with open("/tmp/ocsp2.log") as fh:
        buf = fh.read()
        assert ": unknown" in buf, buf
    with open("/tmp/ocsp3.log") as fh:
        buf = fh.read()
        assert ": revoked" in buf, buf



    ####################################
    ### Switch to Kerberos/LDAP auth ###
    ####################################

    assert os.path.exists("/run/certidude/server.pid")
    pid_certidude = int(open("/run/certidude/server.pid").read())
    os.system("systemctl stop certidude")
    assert not os.path.exists("/run/certidude/server.pid")

    # Install packages
    clean_server()

    # Bootstrap domain controller here,
    # Samba startup takes some time
    assert not os.path.exists("/var/lib/samba/private/secrets.keytab")
    assert not os.path.exists("/etc/krb5.keytab")

    os.system("samba-tool domain provision --server-role=dc --domain=EXAMPLE --realm=EXAMPLE.LAN --host-name=ca")
    assert not os.path.exists("/run/samba/samba.pid")
    os.system("systemctl restart samba-ad-dc")
    os.system("samba-tool user add userbot S4l4k4l4 --given-name='User' --surname='Bot'")
    os.system("samba-tool user add adminbot S4l4k4l4 --given-name='Admin' --surname='Bot'")
    os.system("samba-tool group addmembers 'Domain Admins' adminbot")
    os.system("samba-tool user setpassword administrator --newpassword=S4l4k4l4")
    try:
        os.symlink("/var/lib/samba/private/secrets.keytab", "/etc/krb5.keytab")
    except:
        pass
    os.chmod("/var/lib/samba/private/secrets.keytab", 0o644) # To allow access to certidude server
    if os.path.exists("/etc/krb5.conf"): # Remove the one from krb5-user package
        os.unlink("/etc/krb5.conf")
    os.symlink("/var/lib/samba/private/krb5.conf", "/etc/krb5.conf")
    with open("/etc/resolv.conf", "w") as fh:
        fh.write("nameserver 127.0.0.1\nsearch example.lan\n")
    # TODO: dig -t srv perhaps?


    # Samba bind 636 late (probably generating keypair)
    # so LDAPS connections below will fail
    timeout = 30
    while timeout > 0:
        if os.path.exists("/var/lib/samba/private/tls/cert.pem"):
            break
        sleep(1)
        timeout -= 1
    else:
        assert False, "Samba startup timed out"
    assert os.path.exists("/run/samba/samba.pid")

    # (re)auth against DC
    assert os.system("kdestroy") == 0
    assert not os.path.exists("/tmp/krb5cc_0")
    assert os.system("echo S4l4k4l4 | kinit administrator") == 0
    assert os.path.exists("/tmp/krb5cc_0")

    # Set up HTTP service principal
    os.system("sed -e 's/CA/CA\\nkerberos method = system keytab/' -i /etc/samba/smb.conf ")
    assert os.system("KRB5_KTNAME=FILE:/etc/certidude/server.keytab net ads keytab add HTTP -k") == 0
    assert os.path.exists("/etc/certidude/server.keytab")
    os.system("chown root:certidude /etc/certidude/server.keytab")
    os.system("chmod 640 /etc/certidude/server.keytab")

    assert_cleanliness()
    r = requests.get("http://ca.example.lan/api/")
    assert r.status_code == 502, r.text


    # Bootstrap authority again with:
    # - RSA certificates
    # - Kerberos auth
    # - OCSP disabled
    # - SCEP enabled
    # - CRL disabled

    assert not os.path.exists("/var/lib/certidude/ca_key.pem")
    assert os.system("certidude setup authority --skip-packages -o 'Demola LLC'") == 0
    assert os.path.exists("/var/lib/certidude/ca_key.pem")
    assert os.path.exists("/etc/cron.hourly/certidude")


    # Make modifications to /etc/certidude/server.conf so
    # Certidude would auth against domain controller
    assert os.system("sed -e 's/ldap uri = ldaps:.*/ldap uri = ldaps:\\/\\/ca.example.lan/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/ldap uri = ldap:.*/ldap uri = ldap:\\/\\/ca.example.lan/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/autosign subnets =.*/autosign subnets =/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/machine enrollment subnets =.*/machine enrollment subnets = 0.0.0.0\\/0/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/scep subnets =.*/scep subnets = 0.0.0.0\\/0/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/ocsp subnets =.*/ocsp subnets =/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/crl subnets =.*/crl subnets =/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/address = certificates@example.lan/address =/g' -i /etc/certidude/server.conf") == 0
    assert os.system("sed -e 's/kerberos subnets =.*/kerberos subnets = 0.0.0.0\\/0/g' -i /etc/certidude/server.conf") == 0

    # Update server credential cache
    assert os.system("sed -e 's/dc1/ca/g' -i /etc/cron.hourly/certidude") == 0
    with open("/etc/cron.hourly/certidude") as fh:
        cronjob = fh.read()
        assert "ldap/ca.example.lan" in cronjob, cronjob
    assert os.system("/etc/cron.hourly/certidude") == 0
    assert os.path.exists("/run/certidude/krb5cc")
    assert os.stat("/run/certidude/krb5cc").st_uid != 0, "Incorrect persmissions for /run/certidude/krb5cc"

    # Start certidude backend
    assert os.system("systemctl restart certidude") == 0

    cov_finished = False
    for path in os.listdir("/tmp/"):
        if path.startswith(".coverage.ca.%d." % pid_certidude):
            cov_finished = True
    assert cov_finished, "Didn't find %d in %s" % (pid_certidude, os.listdir("/tmp"))

    assert_cleanliness()

    # Apply /etc/certidude/server.conf changes
    reload(config)
    reload(user)
    reload(authority)

    assert authority.public_key.algorithm == "rsa"
    assert isinstance(user.User.objects, user.ActiveDirectoryUserManager), user.User.objects

    result = runner.invoke(cli, ['users'])
    assert not result.exception, result.output
    assert "user;userbot;User;Bot;userbot@example.lan" in result.output
    assert "admin;adminbot;Admin;Bot;adminbot@example.lan" in result.output
    assert "admin;Administrator;Administrator;;Administrator@example.lan" in result.output


    # Wait for serve to start up
    for j in range(0,10):
        r = requests.get("http://ca.example.lan/api/")
        if r.status_code != 502:
            break
        sleep(1)
    assert r.status_code == 401, "Timed out starting up the API backend"

    # CRL-s disabled now
    r = requests.get("http://ca.example.lan/api/revoked/")
    assert r.status_code == 404, r.text

    # SCEP should be enabled now
    r = requests.get("http://ca.example.lan/api/scep/")
    assert r.status_code == 400
    r = requests.post("http://ca.example.lan/api/scep/")
    assert r.status_code == 405

    # OCSP should be disabled now
    r = requests.get("http://ca.example.lan/api/ocsp/")
    assert r.status_code == 404
    r = requests.post("http://ca.example.lan/api/ocsp/")
    assert r.status_code == 404




    #####################
    ### Kerberos auth ###
    #####################

    # TODO: pip3 install requests-kerberos
    assert_cleanliness()

    assert os.stat("/run/certidude/krb5cc").st_uid != 0, "Incorrect persmissions for /run/certidude/krb5cc"

    from requests_kerberos import HTTPKerberosAuth, OPTIONAL
    auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL, force_preemptive=True)


    # Test Kerberos auth
    r = requests.get("http://ca.example.lan/api/")
    assert r.status_code == 401, r.text
    assert "No Kerberos ticket offered" in r.text, r.text
    r = requests.get("http://ca.example.lan/api/", headers={"Authorization": "Negotiate blerrgh"})
    assert r.status_code == 400, r.text
    assert "Malformed token" in r.text
    r = requests.get("http://ca.example.lan/api/", headers={"Authorization": "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKADk4AAAADw=="})
    assert r.status_code == 400, r.text
    assert "Unsupported authentication mechanism (NTLM" in r.text
    assert os.system("echo S4l4k4l4 | kinit administrator") == 0
    assert os.stat("/run/certidude/krb5cc").st_uid != 0, "Incorrect persmissions for /run/certidude/krb5cc"
    r = requests.get("http://ca.example.lan/api/", auth=auth)
    assert r.status_code == 200, r.text


    #################
    ### LDAP auth ###
    #################

    # Test LDAP bind auth fallback
    usertoken = "Basic dXNlcmJvdDpTNGw0azRsNA=="
    admintoken = "Basic YWRtaW5ib3Q6UzRsNGs0bDQ="

    with open("/etc/ldap/ldap.conf", "w") as fh:
        fh.write("TLS_CACERT /var/lib/samba/private/tls/ca.pem")

    # curl http://ca.example.lan/api/ -u adminbot:S4l4k4l4 -H "User-agent: Android" -H "Referer: http://ca.example.lan"
    r = requests.get("http://ca.example.lan/api/",
        headers={"Authorization":usertoken, "User-Agent": "Android", "Referer":"http://ca.example.lan/"})
    assert r.status_code == 400, r.text
    assert "expected Negotiate" in r.text, r.text


    ###########################
    ### Machine keytab auth ###
    ###########################

    assert_cleanliness()

    mach_pid = os.fork() # Otherwise results in Terminated, needs investigation why
    if not mach_pid:
        clean_client()

        # Test non-matching CN
        result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "somethingelse", "ca.example.lan", "vpn.example.lan"])
        assert not result.exception, result.output

        result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait", "--kerberos"])
        assert result.exception, result.output # Bad request 400

        # With matching CN it should work
        clean_client()

        result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "ca", "ca.example.lan", "vpn.example.lan"])
        assert not result.exception, result.output

        result = runner.invoke(cli, ["enroll", "--skip-self", "--no-wait", "--kerberos"])
        assert not result.exception, result.output
        assert "Writing certificate to:" in result.output, result.output
        return
    else:
        os.waitpid(mach_pid, 0)


    ##################
    ### SCEP tests ###
    ##################

    assert not os.path.exists("/tmp/sscep/ca.pem")

    if not os.path.exists("/tmp/sscep"):
        assert not os.system("git clone  https://github.com/certnanny/sscep /tmp/sscep")
    if not os.path.exists("/tmp/sscep/sscep_dyn"):
        assert not os.system("cd /tmp/sscep && ./Configure && make sscep_dyn")
    assert not os.system("/tmp/sscep/sscep_dyn getca -c /tmp/sscep/ca.pem -u http://ca.example.lan/cgi-bin/pkiclient.exe")
    if not os.path.exists("/tmp/key.pem"):
        assert not os.system("openssl genrsa -out /tmp/key.pem 1024")
    if not os.path.exists("/tmp/req.pem"):
        assert not os.system("echo '.\n.\n.\n.\nGateway\ntest8\n\n\n\n' | openssl req -new -sha256 -key /tmp/key.pem -out /tmp/req.pem")
    assert not os.system("/tmp/sscep/sscep_dyn enroll -c /tmp/sscep/ca.pem -u http://ca.example.lan/cgi-bin/pkiclient.exe -k /tmp/key.pem -r /tmp/req.pem -l /tmp/cert.pem")
    # TODO: test e-mails at this point
    # TODO: add strongswan scep client tests here


    ###################
    ### Final tests ###
    ###################


    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception, result.output
    result = runner.invoke(cli, ['expire'])
    assert not result.exception, result.output

    pid_certidude = int(open("/run/certidude/server.pid").read())
    assert os.system("systemctl stop certidude") == 0

    cov_finished = False
    for path in os.listdir("/tmp/"):
        if path.startswith(".coverage.ca.%d." % pid_certidude):
            cov_finished = True
    assert cov_finished

    assert open("/etc/apparmor.d/local/usr.lib.ipsec.charon").read() == \
       "/etc/certidude/authority/ca.example.lan/client_key.pem r,\n" + \
       "/etc/certidude/authority/ca.example.lan/ca_cert.pem r,\n" + \
       "/etc/certidude/authority/ca.example.lan/client_cert.pem r,\n"
    # TODO: pop mails from /var/mail and check content

    os.system("service nginx stop")
    os.system("service openvpn stop")
    os.system("ipsec stop")

    os.system("certidude token list")
    os.system("certidude token purge")

    clean_server()

if __name__ == "__main__":
    test_cli_setup_authority()
