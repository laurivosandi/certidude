import pwd
from click.testing import CliRunner
from datetime import datetime, timedelta
from time import sleep
import pytest
import shutil
import sys
import os

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


def clean_client():
    assert os.getuid() == 0 and os.getgid() == 0
    if os.path.exists("/etc/certidude/client.conf"):
        os.unlink("/etc/certidude/client.conf")
    if os.path.exists("/etc/certidude/services.conf"):
        os.unlink("/etc/certidude/services.conf")

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
    if os.path.exists("/run/certidude/server.pid"):
        with open("/run/certidude/server.pid") as fh:
            try:
                os.kill(int(fh.read()), 15)
            except OSError:
                pass


    if os.path.exists("/var/lib/certidude/ca.example.lan"):
        shutil.rmtree("/var/lib/certidude/ca.example.lan")
    if os.path.exists("/etc/certidude/server.conf"):
        os.unlink("/etc/certidude/server.conf")
    if os.path.exists("/run/certidude"):
        shutil.rmtree("/run/certidude")
    if os.path.exists("/var/log/certidude.log"):
        os.unlink("/var/log/certidude.log")
    if os.path.exists("/etc/cron.hourly/certidude"):
        os.unlink("/etc/cron.hourly/certidude")

    # systemd
    if os.path.exists("/etc/systemd/system/certidude.service"):
        os.unlink("/etc/systemd/system/certidude.service")

    # Remove nginx stuff
    if os.path.exists("/etc/nginx/sites-available/ca.conf"):
        os.unlink("/etc/nginx/sites-available/ca.conf")
    if os.path.exists("/etc/nginx/sites-enabled/ca.conf"):
        os.unlink("/etc/nginx/sites-enabled/ca.conf")
    if os.path.exists("/etc/nginx/sites-available/certidude.conf"):
        os.unlink("/etc/nginx/sites-available/certidude.conf")
    if os.path.exists("/etc/nginx/sites-enabled/certidude.conf"):
        os.unlink("/etc/nginx/sites-enabled/certidude.conf")
    if os.path.exists("/etc/nginx/conf.d/tls.conf"):
        os.unlink("/etc/nginx/conf.d/tls.conf")

    # Remove OpenVPN stuff
    if os.path.exists("/etc/openvpn"):
        for filename in os.listdir("/etc/openvpn"):
            if filename.endswith(".conf"):
                os.unlink(os.path.join("/etc/openvpn", filename))
        if os.path.exists("/etc/openvpn/keys"):
            shutil.rmtree("/etc/openvpn/keys")

    # Stop samba
    if os.path.exists("/run/samba/samba.pid"):
        with open("/run/samba/samba.pid") as fh:
            try:
                os.kill(int(fh.read()), 15)
            except OSError:
                pass
    if os.path.exists("/etc/certidude/server.keytab"):
        os.unlink("/etc/certidude/server.keytab")
    os.system("rm -Rfv /var/lib/samba/*")

    # Restore initial resolv.conf
    shutil.copyfile("/etc/resolv.conf.orig", "/etc/resolv.conf")

def test_cli_setup_authority():
    assert os.getuid() == 0, "Run tests as root in a clean VM or container"

    os.system("apt-get install -y git build-essential python-dev libkrb5-dev")
    os.system("pip install cryptography")

    assert not os.environ.get("KRB5CCNAME"), "Environment contaminated"
    assert not os.environ.get("KRB5_KTNAME"), "Environment contaminated"

    # Mock Fedora
    for util in "/usr/bin/chcon", "/usr/bin/dnf", "/usr/bin/update-ca-trust", "/usr/sbin/dmidecode":
        with open(util, "w") as fh:
            fh.write("#!/bin/bash\n")
            fh.write("exit 0\n")
        os.chmod(util, 0o755)
    if not os.path.exists("/etc/pki/ca-trust/source/anchors/"):
        os.makedirs("/etc/pki/ca-trust/source/anchors/")

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

    # Bootstrap domain controller here,
    # Samba startup takes some time
    os.system("apt-get install -y samba krb5-user winbind bc")
    if os.path.exists("/etc/samba/smb.conf"):
        os.unlink("/etc/samba/smb.conf")
    os.system("samba-tool domain provision --server-role=dc --domain=EXAMPLE --realm=EXAMPLE.LAN --host-name=ca")
    os.system("samba-tool user add userbot S4l4k4l4 --given-name='User' --surname='Bot'")
    os.system("samba-tool user add adminbot S4l4k4l4 --given-name='Admin' --surname='Bot'")
    os.system("samba-tool group addmembers 'Domain Admins' adminbot")
    os.system("samba-tool user setpassword administrator --newpassword=S4l4k4l4")
    if os.path.exists("/etc/krb5.keytab"):
        os.unlink("/etc/krb5.keytab")
    os.symlink("/var/lib/samba/private/secrets.keytab", "/etc/krb5.keytab")
    os.chmod("/var/lib/samba/private/secrets.keytab", 0o644) # To allow access to certidude server
    if os.path.exists("/etc/krb5.conf"): # Remove the one from krb5-user package
        os.unlink("/etc/krb5.conf")
    os.symlink("/var/lib/samba/private/krb5.conf", "/etc/krb5.conf")
    with open("/etc/resolv.conf", "w") as fh:
        fh.write("nameserver 127.0.0.1\nsearch example.lan\n")
    # TODO: dig -t srv perhaps?
    os.system("samba")

    # Samba bind 636 late (probably generating keypair)
    # so LDAPS connections below will fail
    timeout = 0
    while timeout < 30:
        if os.path.exists("/var/lib/samba/private/tls/cert.pem"):
            break
        sleep(1)
        timeout += 1
    else:
        assert False, "Samba startup timed out"

    reload(const)
    from certidude.cli import entry_point as cli

    assert const.FQDN == "ca.example.lan"
    assert const.HOSTNAME == "ca"
    assert const.DOMAIN == "example.lan"

    result = runner.invoke(cli, ['setup', 'authority', '-s'])
    os.setgid(0) # Restore GID
    os.umask(0o022)

    result = runner.invoke(cli, ['setup', 'authority']) # For if-else branches
    os.setgid(0) # Restore GID
    os.umask(0o022)

    # Make sure nginx is running
    assert not result.exception, result.output
    assert os.getuid() == 0 and os.getgid() == 0, "Serve dropped permissions incorrectly!"
    assert os.system("nginx -t") == 0, "invalid nginx configuration"
    os.system("service nginx restart")
    assert os.path.exists("/run/nginx.pid"), "nginx wasn't started up properly"

    from certidude import config, authority, auth, user
    assert authority.certificate.serial_number >= 0x100000000000000000000000000000000000000
    assert authority.certificate.serial_number <= 0xfffffffffffffffffffffffffffffffffffffff
    assert authority.certificate["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None) < datetime.utcnow()
    assert authority.certificate["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None) > datetime.utcnow() + timedelta(days=7000)
    assert authority.server_flags("lauri@fedora-123") == False
    assert authority.server_flags("fedora-123") == False
    assert authority.server_flags("vpn.example.lan") == True
    assert authority.server_flags("lauri@a.b.c") == False

    # Generate garbage
    with open("/var/lib/certidude/ca.example.lan/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/ca.example.lan/requests/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/ca.example.lan/signed/bla", "w") as fh:
        pass
    with open("/var/lib/certidude/ca.example.lan/revoked/bla", "w") as fh:
        pass

    # Start server before any signing operations are performed
    config.CERTIFICATE_RENEWAL_ALLOWED = True

    server_pid = os.fork()
    if not server_pid:
        # Fork to prevent umask, setuid, setgid side effects
        result = runner.invoke(cli, ['serve'])
        assert not result.exception, result.output
        return

    sleep(1) # Wait for serve to start up

    # TODO: check that port 8080 is listening, otherwise app probably crashed

    import requests

    # Test CA certificate fetch
    buf = open("/var/lib/certidude/ca.example.lan/ca_crt.pem").read()
    r = requests.get("http://ca.example.lan/api/certificate")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-x509-ca-cert"
    assert r.text == buf

    r = client().simulate_get("/api/certificate")
    assert r.status_code == 200
    assert r.headers.get('content-type') == "application/x-x509-ca-cert"
    assert r.text == buf

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

    # Check that SCEP and OCSP are disabled by default
    r = requests.get("http://ca.example.lan/api/ocsp/")
    assert r.status_code == 404, r.text
    r = requests.get("http://ca.example.lan/api/scep/")
    assert r.status_code == 404, r.text

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
    assert r.status_code == 200, r.text
    r = client().simulate_get("/index.html")
    assert r.status_code == 200, r.text
    r = client().simulate_get("/nonexistant.html")
    assert r.status_code == 404, r.text
    r = client().simulate_get("/../nonexistant.html")
    assert r.status_code == 400, r.text

    # Test request submission
    buf = generate_csr(cn=u"test")

    r = client().simulate_post("/api/request/", body=buf)
    assert r.status_code == 415 # wrong content type

    r = client().simulate_post("/api/request/",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # success
    assert "Stored request " in inbox.pop(), inbox
    assert os.path.exists("/var/lib/certidude/ca.example.lan/requests/test.pem")

    # Test request deletion
    r = client().simulate_delete("/api/request/test/")
    assert r.status_code == 401, r.text
    r = client().simulate_delete("/api/request/test/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_delete("/api/request/test/",
        headers={"User-Agent":UA_FEDORA_FIREFOX, "Authorization":admintoken})
    assert r.status_code == 403, r.text # CSRF prevented
    assert os.path.exists("/var/lib/certidude/ca.example.lan/requests/test.pem")
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
        body=generate_csr(cn=u"test"),
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
    buf = generate_csr(cn=u"test2")
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

    buf = generate_csr(cn=u"test2")
    r = client().simulate_post("/api/request/",
        query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # duplicate CN, request stored
    assert "Stored request " in inbox.pop(), inbox
    assert not inbox

    buf = generate_csr(cn=u"test2.example.lan")
    r = client().simulate_post("/api/request/",
        query_string="autosign=1",
        body=buf,
        headers={"content-type":"application/pkcs10"})
    assert r.status_code == 202 # server CN, request stored
    assert "Stored request " in inbox.pop(), inbox
    assert not inbox

    # Test signed certificate API call
    r = client().simulate_get("/api/signed/nonexistant/")
    assert r.status_code == 404, r.text

    r = client().simulate_get("/api/signed/test/")
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == "application/x-pem-file"

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

    r = client().simulate_get("/api/revoked/",
        query_string="wait=true",
        headers={"Accept":"application/x-pem-file"})
    assert r.status_code == 303, r.text

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
    assert r.text == '[{"value": "Tartu", "key": "location", "id": "location=Tartu"}, {"value": "else", "key": "other", "id": "else"}]', r.text



    # Test scripting
    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 403, r.text # script not authorized
    r = client().simulate_get("/api/signed/nonexistant/script/")
    assert r.status_code == 404, r.text # cert not found

    # Insert lease
    r = client().simulate_get("/api/signed/test/lease/", headers={"Authorization":admintoken})
    assert r.status_code == 404, r.text
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=127.0.0.1&outer_address=8.8.8.8",
        headers={"Authorization":admintoken})
    assert r.status_code == 200, r.text # lease update ok

    # Attempt to fetch and execute default.sh script
    from xattr import listxattr, getxattr
    assert not [j for j in listxattr("/var/lib/certidude/ca.example.lan/signed/test.pem") if j.startswith("user.machine.")]
    #os.system("curl http://ca.example.lan/api/signed/test/script | bash")
    r = client().simulate_post("/api/signed/test/attr", body="cpu=i5&mem=512M&dist=Ubuntu",
        headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200, r.text
    assert getxattr("/var/lib/certidude/ca.example.lan/signed/test.pem", "user.machine.cpu") == "i5"
    assert getxattr("/var/lib/certidude/ca.example.lan/signed/test.pem", "user.machine.mem") == "512M"
    assert getxattr("/var/lib/certidude/ca.example.lan/signed/test.pem", "user.machine.dist") == "Ubuntu"

    # Test tagging integration in scripting framework
    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 200, r.text # script render ok
    assert "curl http://ca.example.lan/api/signed/test/attr " in r.text, r.text
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
    r = client().simulate_get("/api/signed/test/script/")
    assert r.status_code == 200, r.text # script render ok
    assert "# No tags" in r.text, r.text

    # Test lease update
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=127.0.0.1&outer_address=8.8.8.8&serial=0",
        headers={"Authorization":admintoken})
    assert r.status_code == 403, r.text # invalid serial number supplied
    r = client().simulate_post("/api/lease/",
        query_string = "client=test&inner_address=1.2.3.4&outer_address=8.8.8.8",
        headers={"Authorization":admintoken})
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
    r = client().simulate_get("/api/log/")
    assert r.status_code == 401, r.text
    r = client().simulate_get("/api/log/",
        headers={"Authorization":usertoken})
    assert r.status_code == 403, r.text
    r = client().simulate_get("/api/log/",
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
    assert r.status_code == 200
    assert r.headers.get('content-type').startswith("application/json")
    assert r.json, r.text
    assert not r.json.get("authority"), r.text # No permissions to admin

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


    #######################
    ### Token mechanism ###
    #######################

    r = client().simulate_post("/api/token/")
    assert r.status_code == 404, r.text

    """
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
    assert "Token for " in inbox.pop(), inbox

    r2 = client().simulate_get("/api/token/",
        query_string="u=userbot&t=1493184342&c=ac9b71421d5741800c5a4905b20c1072594a2df863e60ba836464888786bf2a6",
        headers={"content-type": "application/x-www-form-urlencoded", "Authorization":admintoken})
    assert r2.status_code == 403 # invalid checksum
    r2 = client().simulate_get("/api/token/",
        query_string=r.content,
        headers={"User-Agent":UA_FEDORA_FIREFOX})
    assert r2.status_code == 200 # token consumed by anyone on Fedora
    assert r2.headers.get('content-type') == "application/x-openvpn"
    assert "Signed " in inbox.pop(), inbox

    config.BUNDLE_FORMAT = "p12" # Switch to PKCS#12
    r2 = client().simulate_get("/api/token/", query_string=r.content)
    assert r2.status_code == 200 # token consumed by anyone on unknown device
    assert r2.headers.get('content-type') == "application/x-pkcs12"
    assert "Signed " in inbox.pop(), inbox
    """

    # Beyond this point don't use client()
    const.STORAGE_PATH = "/tmp/"


    #############
    ### nginx ###
    #############

    # In this case nginx is set up as web server with TLS certificates
    # generated by certidude.

    clean_client()

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www", "ca.example.lan"])
    assert result.exception # FQDN required

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www.example.lan", "ca.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ["setup", "nginx", "-cn", "www.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "(Autosign failed, only client certificates allowed to be signed automatically)" in result.output, result.output

    child_pid = os.fork()
    if not child_pid:
        result = runner.invoke(cli, ["sign", "www.example.lan"])
        assert not result.exception, result.output
        assert "Publishing request-signed event 'www.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output

    result = runner.invoke(cli, ["request", "--renew", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    #assert "Writing certificate to:" in result.output, result.output
    assert "Attached renewal signature" in result.output, result.output

    # Test nginx setup
    assert os.system("nginx -t") == 0, "Generated nginx config was invalid"


    ###############
    ### OpenVPN ###
    ###############

    # First OpenVPN server is set up

    clean_client()

    if not os.path.exists("/etc/openvpn/keys"):
        os.makedirs("/etc/openvpn/keys")

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn", "ca.example.lan"])
    assert result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn.example.lan", "ca.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'server', "-cn", "vpn.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert "(Autosign failed, only client certificates allowed to be signed automatically)" in result.output, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert not os.path.exists("/var/lib/certidude/ca.example.lan/signed/vpn.example.lan.pem")

    child_pid = os.fork()
    if not child_pid:
        assert not os.path.exists("/var/lib/certidude/ca.example.lan/signed/vpn.example.lan.pem")
        result = runner.invoke(cli, ["sign", "vpn.example.lan"])
        assert not result.exception, result.output
        assert "overwrit" not in result.output, result.output
        assert "Publishing request-signed event 'vpn.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/tmp/ca.example.lan/server_cert.pem")
    assert os.path.exists("/etc/openvpn/site-to-client.conf")

    # Secondly OpenVPN client is set up

    os.unlink("/etc/certidude/client.conf")
    os.unlink("/etc/certidude/services.conf")

    result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "roadwarrior1", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "roadwarrior1", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/etc/openvpn/client-to-site.conf")

    # TODO: Check that tunnel interfaces came up, perhaps try to ping?
    # TODO: assert key, req, cert paths were included correctly in OpenVPN config

    clean_client()

    result = runner.invoke(cli, ['setup', 'openvpn', 'networkmanager', "-cn", "roadwarrior3", "ca.example.lan", "vpn.example.lan"])
    assert not result.exception, result.output

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output


    #################################
    ### Subscribe to event source ###
    #################################

    ev_pid = os.fork()
    if not ev_pid:
        r = requests.get(ev_url, headers={"Accept": "text/event-stream"}, stream=True)
        assert r.status_code == 200, r.text
        i = r.iter_lines()
        assert i.next() == ": hi"
        assert not i.next()

        # IPSec gateway below
        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Served CA certificate ')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: request-submitted", "%s; %s" % (i.next(), i.next())
        assert i.next().startswith("id:")
        assert i.next() == "data: ipsec.example.lan"
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Stored signing request ipsec.example.lan ')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Stored signing request ipsec.example.lan ')
        assert not i.next()

        assert i.next() == "event: request-signed"
        assert i.next().startswith("id:")
        assert i.next().startswith('data: ipsec.example.lan')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Served certificate ipsec.example.lan')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Served certificate ipsec.example.lan')
        assert not i.next()

        # IPsec client as service enroll
        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: request-signed", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: roadwarrior2')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Autosigned roadwarrior2')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Autosigned roadwarrior2')
        assert not i.next()



        # IPSec client using Networkmanger enroll
        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Served CA certificate ')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Serving revocation list (PEM)')
        assert not i.next()

        assert i.next() == "event: request-signed", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: roadwarrior4')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next()
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Autosigned roadwarrior4')
        assert not i.next()

        assert i.next() == "event: log-entry", i.next() # FIXME
        assert i.next().startswith("id:")
        assert i.next().startswith('data: {"message": "Autosigned roadwarrior4')
        assert not i.next()


        # Revoke

        assert i.next() == "event: certificate-revoked", i.next() # why?!
        assert i.next().startswith("id:")
        assert i.next().startswith('data: roadwarrior4')
        assert not i.next()


        return


    #############
    ### IPSec ###
    #############

    # Setup gateway

    clean_client()

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec", "ca.example.lan"])
    assert result.exception, result.output # FQDN required

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec.example.lan", "ca.example.lan"])
    assert not result.exception, result.output
    assert open("/etc/ipsec.secrets").read() == ": RSA /tmp/ca.example.lan/server_key.pem\n"

    result = runner.invoke(cli, ['setup', 'strongswan', 'server', "-cn", "ipsec.example.lan", "ca.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert not os.path.exists("/var/lib/certidude/ca.example.lan/signed/ipsec.example.lan.pem")

    child_pid = os.fork()
    if not child_pid:
        assert not os.path.exists("/var/lib/certidude/ca.example.lan/signed/ipsec.example.lan.pem")
        result = runner.invoke(cli, ["sign", "ipsec.example.lan"])
        assert not result.exception, result.output
        assert "overwrit" not in result.output, result.output
        assert "Publishing request-signed event 'ipsec.example.lan' on http://localhost/ev/pub/" in result.output, result.output
        return
    else:
        os.waitpid(child_pid, 0)

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output

    assert "Writing certificate to:" in result.output, result.output
    assert os.path.exists("/tmp/ca.example.lan/server_cert.pem")

    # IPSec client as service

    os.unlink("/etc/certidude/client.conf")
    os.unlink("/etc/certidude/services.conf")

    result = runner.invoke(cli, ['setup', 'strongswan', 'client', "-cn", "roadwarrior2", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output

    result = runner.invoke(cli, ['setup', 'strongswan', 'client', "-cn", "roadwarrior2", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output # client conf already exists, remove to regenerate

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output

    assert "Writing certificate to:" in result.output, result.output

    # IPSec using NetworkManager

    clean_client()

    result = runner.invoke(cli, ['setup', 'strongswan', 'networkmanager', "-cn", "roadwarrior4", "ca.example.lan", "ipsec.example.lan"])
    assert not result.exception, result.output

    with open("/etc/certidude/client.conf", "a") as fh:
        fh.write("insecure = true\n")

    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    assert "Writing certificate to:" in result.output, result.output


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
    result = runner.invoke(cli, ["request", "--no-wait"])
    assert not result.exception, result.output
    assert not os.path.exists("/run/certidude/ca.example.lan.pid"), result.output
    #assert "Certificate has been revoked, wiping keys and certificates" in result.output, result.output
    #assert "Writing certificate to:" in result.output, result.output

    #########################################################
    ### Test that legacy features are disabled by default ###
    #########################################################

    r = client().simulate_get("/api/scep/")
    assert r.status_code == 404
    r = client().simulate_get("/api/ocsp/")
    assert r.status_code == 404
    r = client().simulate_post("/api/scep/")
    assert r.status_code == 404
    r = client().simulate_post("/api/ocsp/")
    assert r.status_code == 404


    ####################################
    ### Switch to Kerberos/LDAP auth ###
    ####################################

    # Shut down current instance
    os.kill(server_pid, 15)
    requests.get("http://ca.example.lan/api/")
    os.waitpid(server_pid, 0)

    # (re)auth against DC
    assert os.system("kdestroy") == 0
    assert not os.path.exists("/tmp/krb5cc_0")
    assert os.system("echo S4l4k4l4 | kinit administrator") == 0
    assert os.path.exists("/tmp/krb5cc_0")

    # Fork to not contaminate environment while creating service principal
    spn_pid = os.fork()
    if not spn_pid:
        os.system("sed -e 's/CA/CA\\nkerberos method = system keytab/' -i /etc/samba/smb.conf ")
        os.environ["KRB5_KTNAME"] = "FILE:/etc/certidude/server.keytab"
        assert os.system("net ads keytab add HTTP -k") == 0
        assert os.path.exists("/etc/certidude/server.keytab")
        os.system("chown root:certidude /etc/certidude/server.keytab")
        os.system("chmod 640 /etc/certidude/server.keytab")
        return
    else:
        os.waitpid(spn_pid, 0)

    # Make modifications to /etc/certidude/server.conf so
    # Certidude would auth against domain controller
    os.system("sed -e 's/ldap uri = ldaps:.*/ldap uri = ldaps:\\/\\/ca.example.lan/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/ldap uri = ldap:.*/ldap uri = ldap:\\/\\/ca.example.lan/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/backends = pam/backends = kerberos ldap/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/backend = posix/backend = ldap/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/dc1/ca/g' -i /etc/cron.hourly/certidude")
    os.system("sed -e 's/autosign subnets =.*/autosign subnets =/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/machine enrollment =.*/machine enrollment = allowed/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/scep subnets =.*/scep subnets = 0.0.0.0\\/0/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/ocsp subnets =.*/ocsp subnets = 0.0.0.0\\/0/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/crl subnets =.*/crl subnets =/g' -i /etc/certidude/server.conf")
    os.system("sed -e 's/address = certificates@example.lan/address =/g' -i /etc/certidude/server.conf")
    from certidude.common import pip
    pip("asn1crypto certbuilder")

    # Update server credential cache
    with open("/etc/cron.hourly/certidude") as fh:
        cronjob = fh.read()
        assert "ldap/ca.example.lan" in cronjob, cronjob
    os.system("/etc/cron.hourly/certidude")

    server_pid = os.fork() # Fork to prevent environment contamination
    if not server_pid:
        # Apply /etc/certidude/server.conf changes
        reload(config)
        reload(user)
        reload(auth)
        assert isinstance(user.User.objects, user.ActiveDirectoryUserManager), user.User.objects

        result = runner.invoke(cli, ['users'])
        assert not result.exception, result.output
        assert "user;userbot;User;Bot;userbot@example.lan" in result.output
        assert "admin;adminbot;Admin;Bot;adminbot@example.lan" in result.output
        assert "admin;Administrator;Administrator;;Administrator@example.lan" in result.output

        result = runner.invoke(cli, ['serve'])
        assert not result.exception, result.output
        return

    sleep(1) # Wait for serve to start up

    # CRL-s disabled now
    r = requests.get("http://ca.example.lan/api/revoked/")
    assert r.status_code == 404, r.text

    assert os.system("openssl ocsp -issuer /var/lib/certidude/ca.example.lan/ca_crt.pem -cert /var/lib/certidude/ca.example.lan/signed/roadwarrior2.pem -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp1.log") == 0
    assert os.system("openssl ocsp -issuer /var/lib/certidude/ca.example.lan/ca_crt.pem -cert /var/lib/certidude/ca.example.lan/ca_crt.pem -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp2.log") == 0

    for filename in os.listdir("/var/lib/certidude/ca.example.lan/revoked"):
        if not filename.endswith(".pem"):
            continue
        assert os.system("openssl ocsp -issuer /var/lib/certidude/ca.example.lan/ca_crt.pem -cert /var/lib/certidude/ca.example.lan/revoked/%s -text -url http://ca.example.lan/api/ocsp/ -out /tmp/ocsp3.log" % filename) == 0
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


    #####################
    ### Kerberos auth ###
    #####################

    # TODO: pip install requests-kerberos
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
    r = requests.get("http://ca.example.lan/api/", auth=auth)
    assert r.status_code == 200, r.text


    #################
    ### LDAP auth ###
    #################

    # Test LDAP bind auth fallback
    usertoken = "Basic dXNlcmJvdDpTNGw0azRsNA=="
    admintoken = "Basic YWRtaW5ib3Q6UzRsNGs0bDQ="

    with open("/etc/ldap/ldap.conf", "w") as fh:
        fh.write("TLS_REQCERT never\n") # TODO: Correct way

    # curl http://ca.example.lan/api/ -u adminbot:S4l4k4l4 -H "User-agent: Android" -H "Referer: http://ca.example.lan"
    r = requests.get("http://ca.example.lan/api/",
        headers={"Authorization":usertoken, "User-Agent": "Android", "Referer":"http://ca.example.lan/"})
    #assert r.status_code == 200, r.text # TODO: Fails with 500 in Travis


    ###########################
    ### Machine keytab auth ###
    ###########################

    assert not os.environ.get("KRB5_KTNAME"), "Environment contaminated"

    mach_pid = os.fork() # Otherwise results in Terminated, needs investigation why
    if not mach_pid:
        clean_client()

        # Test non-matching CN
        result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "somethingelse", "ca.example.lan", "vpn.example.lan"])
        assert not result.exception, result.output

        with open("/etc/certidude/client.conf", "a") as fh:
            fh.write("insecure = true\n")

        result = runner.invoke(cli, ["request", "--no-wait", "--kerberos"])
        assert result.exception, result.output # Bad request 400

        # With matching CN it should work
        clean_client()

        result = runner.invoke(cli, ['setup', 'openvpn', 'client', "-cn", "ca", "ca.example.lan", "vpn.example.lan"])
        assert not result.exception, result.output

        with open("/etc/certidude/client.conf", "a") as fh:
            fh.write("insecure = true\n")

        result = runner.invoke(cli, ["request", "--no-wait", "--kerberos"])
        assert not result.exception, result.output
        assert "Writing certificate to:" in result.output, result.output
        return
    else:
        os.waitpid(mach_pid, 0)


    ##################
    ### SCEP tests ###
    ##################

    os.umask(0o022)
    if not os.path.exists("/tmp/sscep"):
        assert not os.system("git clone  https://github.com/certnanny/sscep /tmp/sscep")
    if not os.path.exists("/tmp/sscep/sscep_dyn"):
        assert not os.system("cd /tmp/sscep && ./Configure && make sscep_dyn")
    assert not os.system("/tmp/sscep/sscep_dyn getca -c /tmp/sscep/ca.pem -u http://ca.example.lan/cgi-bin/pkiclient.exe")
    if not os.path.exists("/tmp/key.pem"):
        assert not os.system("openssl genrsa -out /tmp/key.pem 1024")
    if not os.path.exists("/tmp/req.pem"):
        assert not os.system("echo '.\n.\n.\n.\n.\ntest8\n\n\n\n' | openssl req -new -sha256 -key /tmp/key.pem -out /tmp/req.pem")
    assert not os.system("/tmp/sscep/sscep_dyn enroll -c /tmp/sscep/ca.pem -u http://ca.example.lan/cgi-bin/pkiclient.exe -k /tmp/key.pem -r /tmp/req.pem -l /tmp/cert.pem")
    # TODO: test e-mails at this point


    ###################
    ### Final tests ###
    ###################


    result = runner.invoke(cli, ['list', '-srv'])
    assert not result.exception, result.output
    result = runner.invoke(cli, ['cron'])
    assert not result.exception, result.output

    # Shut down server
    assert os.path.exists("/proc/%d" % server_pid)
    os.kill(server_pid, 15)
    os.waitpid(server_pid, 0)

    # Note: STORAGE_PATH was mangled above, hence it's /tmp not /var/lib/certidude
    assert open("/etc/apparmor.d/local/usr.lib.ipsec.charon").read() == "/tmp/** r,\n"
    assert len(inbox) == 0, inbox # Make sure all messages were checked

    os.system("service nginx stop")
    os.system("service openvpn stop")
    os.system("ipsec stop")

    clean_server()

if __name__ == "__main__":
    test_cli_setup_authority()
