
import click
import os
import subprocess
import tempfile
from base64 import b64encode
from datetime import datetime, timedelta
from configparser import ConfigParser

def selinux_fixup(path):
    """
    Fix OpenVPN credential store security context on Fedora
    """
    if not os.path.exists("/sys/fs/selinux"):
        return
    cmd = "chcon", "--type=home_cert_t", path
    subprocess.call(cmd)

def certidude_request_certificate(server, system_keytab_required, key_path, request_path, certificate_path, authority_path, revocations_path, common_name, autosign=False, wait=False, bundle=False, renew=False, insecure=False):
    """
    Exchange CSR for certificate using Certidude HTTP API server
    """
    import requests
    from certidude import errors, const
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID

    # Create directories
    for path in key_path, request_path, certificate_path, authority_path, revocations_path:
        dir_path = os.path.dirname(path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

    # Set up URL-s
    request_params = set()
    if autosign:
        request_params.add("autosign=true")
    if wait:
        request_params.add("wait=forever")

    # Expand ca.example.com
    scheme = "http" if insecure else "https" # TODO: Expose in CLI
    authority_url = "%s://%s/api/certificate/" % (scheme, server)
    request_url = "%s://%s/api/request/" % (scheme, server)
    revoked_url = "%s://%s/api/revoked/" % (scheme, server)

    if request_params:
        request_url = request_url + "?" + "&".join(request_params)

    if os.path.exists(authority_path):
        click.echo("Found authority certificate in: %s" % authority_path)
    else:
        click.echo("Attempting to fetch authority certificate from %s" % authority_url)
        try:
            r = requests.get(authority_url,
                headers={"Accept": "application/x-x509-ca-cert,application/x-pem-file"})
            x509.load_pem_x509_certificate(r.content, default_backend())
        except:
            raise
        #    raise ValueError("Failed to parse PEM: %s" % r.text)
        authority_partial = tempfile.mktemp(prefix=authority_path + ".part")
        with open(authority_partial, "w") as oh:
            oh.write(r.content)
        click.echo("Writing authority certificate to: %s" % authority_path)
        selinux_fixup(authority_partial)
        os.rename(authority_partial, authority_path)

    # Fetch certificate revocation list
    r = requests.get(revoked_url, headers={'accept': 'application/x-pem-file'}, stream=True)
    assert r.status_code == 200, "Failed to fetch CRL from %s, got %s" % (revoked_url, r.text)
    click.echo("Fetching CRL from %s to %s" % (revoked_url, revocations_path))
    revocations_partial = tempfile.mktemp(prefix=revocations_path + ".part")
    with open(revocations_partial, 'wb') as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    if subprocess.call(("openssl", "crl", "-CAfile", authority_path, "-in", revocations_partial, "-noout")):
        raise ValueError("Failed to verify CRL in %s" % revocations_partial)
    else:
        # TODO: Check monotonically increasing CRL number
        click.echo("Certificate revocation list passed verification")
        selinux_fixup(revocations_partial)
        os.rename(revocations_partial, revocations_path)

    # Check if we have been inserted into CRL
    if os.path.exists(certificate_path):
        cert = x509.load_pem_x509_certificate(open(certificate_path).read(), default_backend())

        for revocation in x509.load_pem_x509_crl(open(revocations_path).read(), default_backend()):
            extension, = revocation.extensions

            if revocation.serial_number == cert.serial:
                if extension.value.reason == x509.ReasonFlags.certificate_hold:
                    # Don't do anything for now
                    # TODO: disable service
                    break

                # Disable the client if operation has been ceased
                if extension.value.reason == x509.ReasonFlags.cessation_of_operation:
                    if os.path.exists("/etc/certidude/client.conf"):
                        clients.readfp(open("/etc/certidude/client.conf"))
                        if clients.has_section(server):
                            clients.set(server, "trigger", "operation ceased")
                            clients.write(open("/etc/certidude/client.conf", "w"))
                            click.echo("Authority operation ceased, disabling in /etc/certidude/client.conf")
                    # TODO: Disable related services
                    return

                click.echo("Certificate has been revoked, wiping keys and certificates!")
                if os.path.exists(key_path):
                    os.remove(key_path)
                if os.path.exists(request_path):
                    os.remove(request_path)
                if os.path.exists(certificate_path):
                    os.remove(certificate_path)
                break
        else:
            click.echo("Certificate does not seem to be revoked. Good!")


    try:
        request_buf = open(request_path).read()
        request = x509.load_pem_x509_csr(request_buf, default_backend())
        click.echo("Found signing request: %s" % request_path)
        with open(key_path) as fh:
            key = serialization.load_pem_private_key(
                fh.read(),
                password=None,
                backend=default_backend())
    except EnvironmentError:

        # Construct private key
        click.echo("Generating 4096-bit RSA key...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Dump private key
        key_partial = tempfile.mktemp(prefix=key_path + ".part")
        os.umask(0o077)
        with open(key_partial, "wb") as fh:
            fh.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Set subject name attributes
        names = [x509.NameAttribute(NameOID.COMMON_NAME, common_name.decode("utf-8"))]

        # Construct CSR
        csr = x509.CertificateSigningRequestBuilder(
            ).subject_name(x509.Name(names))

        # Sign & dump CSR
        os.umask(0o022)
        request_partial = tempfile.mktemp(prefix=request_path + ".part")
        with open(request_partial, "wb") as f:
            f.write(csr.sign(key, hashes.SHA256(), default_backend()).public_bytes(serialization.Encoding.PEM))

        click.echo("Writing private key to: %s" % key_path)
        selinux_fixup(key_partial)
        os.rename(key_partial, key_path)

        click.echo("Writing certificate signing request to: %s" % request_path)
        os.rename(request_partial, request_path)

    # We have CSR now, save the paths to client.conf so we could:
    # Update CRL, renew certificate, maybe something extra?

    if os.path.exists(certificate_path):
        cert_buf = open(certificate_path).read()
        cert = x509.load_pem_x509_certificate(cert_buf, default_backend())
        lifetime = (cert.not_valid_after - cert.not_valid_before)
        overlap = lifetime / 4 # TODO: Make overlap configurable
        if datetime.now() > cert.not_valid_after - overlap:
            click.echo("Certificate expired %s" % cert.not_valid_after)
            renew = True
        else:
            click.echo("Found valid certificate: %s" % certificate_path)
            if not renew: # Don't do anything if renewal wasn't requested explicitly
                return

    # If machine is joined to domain attempt to present machine credentials for authentication
    if system_keytab_required:
        os.environ["KRB5CCNAME"]="/tmp/ca.ticket"
        # If Samba configuration exists assume NetBIOS name was used in keytab
        if os.path.exists("/etc/samba/smb.conf"):
            from configparser import ConfigParser
            cp = ConfigParser(delimiters=("="))
            cp.readfp(open("/etc/samba/smb.conf"))
            name = cp.get("global", "netbios name")
            os.system("kinit -S HTTP/%s -k %s$" % (server, name))
        else:
            os.system("kinit -S HTTP/%s -k %s$" % (server, const.HOSTNAME.lower())) # Mac OS X
            os.system("kinit -S HTTP/%s -k %s$" % (server, const.HOSTNAME.upper())) # Fedora /w SSSD
        from requests_kerberos import HTTPKerberosAuth, OPTIONAL
        auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL, force_preemptive=True)
    else:
        auth = None

    click.echo("Submitting to %s, waiting for response..." % request_url)
    headers={
        "Content-Type": "application/pkcs10",
        "Accept": "application/x-x509-user-cert,application/x-pem-file"
    }

    if renew:
        signer = key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        signer.update(cert_buf)
        signer.update(request_buf)
        headers["X-Renewal-Signature"] = b64encode(signer.finalize())
        click.echo("Attached renewal signature %s" % headers["X-Renewal-Signature"])

    submission = requests.post(request_url, auth=auth, data=open(request_path), headers=headers)

    # Destroy service ticket
    if os.path.exists("/tmp/ca.ticket"):
        os.system("kdestroy")

    if submission.status_code == requests.codes.ok:
        pass
    if submission.status_code == requests.codes.accepted:
        # Server stored the request for processing (202 Accepted), but waiting was not requested, hence quitting for now
        return
    if submission.status_code == requests.codes.conflict:
        raise errors.DuplicateCommonNameError("Different signing request with same CN is already present on server, server refuses to overwrite")
    elif submission.status_code == requests.codes.gone:
        # Should the client retry or disable request submission?
        raise ValueError("Server refused to sign the request") # TODO: Raise proper exception
    else:
        submission.raise_for_status()

    try:
        cert = x509.load_pem_x509_certificate(submission.text.encode("ascii"), default_backend())
    except: # TODO: catch correct exceptions
        raise ValueError("Failed to parse PEM: %s" % submission.text)

    os.umask(0o022)
    certificate_partial = tempfile.mktemp(prefix=certificate_path + ".part")
    with open(certificate_partial, "w") as fh:
        # Dump certificate
        fh.write(submission.text)

        # Bundle CA certificate, necessary for nginx
        if bundle:
            with open(authority_path) as ch:
                fh.write(ch.read())

    click.echo("Writing certificate to: %s" % certificate_path)
    selinux_fixup(certificate_partial)
    os.rename(certificate_partial, certificate_path)

    # TODO: Validate fetched certificate against CA
    # TODO: Check that recevied certificate CN and pubkey match
    # TODO: Check file permissions
