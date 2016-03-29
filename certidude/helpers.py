
import click
import os
import requests
import subprocess
import tempfile
from certidude import errors
from certidude.wrappers import Certificate, Request
from configparser import ConfigParser
from OpenSSL import crypto

def certidude_request_certificate(server, key_path, request_path, certificate_path, authority_path, revocations_path, common_name, org_unit=None, email_address=None, given_name=None, surname=None, autosign=False, wait=False, key_usage=None, extended_key_usage=None, ip_address=None, dns=None, bundle=False):
    """
    Exchange CSR for certificate using Certidude HTTP API server
    """

    # Set up URL-s
    request_params = set()
    if autosign:
        request_params.add("autosign=true")
    if wait:
        request_params.add("wait=forever")

    # Expand ca.example.com
    authority_url = "http://%s/api/certificate/" % server
    request_url = "http://%s/api/request/" % server
    revoked_url = "http://%s/api/revoked/" % server

    if request_params:
        request_url = request_url + "?" + "&".join(request_params)

    if os.path.exists(authority_path):
        click.echo("Found authority certificate in: %s" % authority_path)
    else:
        click.echo("Attempting to fetch authority certificate from %s" % authority_url)
        try:
            r = requests.get(authority_url,
                    headers={"Accept": "application/x-x509-ca-cert,application/x-pem-file"})
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, r.text)
        except crypto.Error:
            raise ValueError("Failed to parse PEM: %s" % r.text)
        authority_partial = tempfile.mktemp(prefix=authority_path + ".part")
        with open(authority_partial, "w") as oh:
            oh.write(r.text)
        click.echo("Writing authority certificate to: %s" % authority_path)
        os.rename(authority_partial, authority_path)

    # Fetch certificate revocation list
    r = requests.get(revoked_url, headers={'accept': 'application/x-pem-file'}, stream=True)
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
        os.rename(revocations_partial, revocations_path)

    # Check if we have been inserted into CRL
    if os.path.exists(certificate_path):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate_path).read())
        revocation_list = crypto.load_crl(crypto.FILETYPE_PEM, open(revocations_path).read())
        for revocation in revocation_list.get_revoked():
            if int(revocation.get_serial(), 16) == cert.get_serial_number():
                if revocation.get_reason() == "Certificate Hold": # TODO: 'Remove From CRL'
                    # TODO: Disable service for time being
                    click.echo("Certificate put on hold, doing nothing for now")
                    break

                # Disable the client if operation has been ceased or
                # the certificate has been superseded by other
                if revocation.get_reason() in ("Cessation Of Operation", "Superseded"):
                    if os.path.exists("/etc/certidude/client.conf"):
                        clients.readfp(open("/etc/certidude/client.conf"))
                        if clients.has_section(server):
                            clients.set(server, "trigger", "operation ceased")
                            clients.write(open("/etc/certidude/client.conf", "w"))
                            click.echo("Authority operation ceased, disabling in /etc/certidude/client.conf")
                    # TODO: Disable related services
                if revocation.get_reason() in ("CA Compromise", "AA Compromise"):
                    if os.path.exists(authority_path):
                        os.remove(key_path)

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
        request = Request(open(request_path))
        click.echo("Found signing request: %s" % request_path)
    except EnvironmentError:

        # Construct private key
        click.echo("Generating 4096-bit RSA key...")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        # Dump private key
        key_partial = tempfile.mktemp(prefix=key_path + ".part")
        os.umask(0o077)
        with open(key_partial, "wb") as fh:
            fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        # Construct CSR
        csr = crypto.X509Req()
        csr.set_version(2) # Corresponds to X.509v3
        csr.set_pubkey(key)
        csr.get_subject().CN = common_name

        request = Request(csr)

        # Set subject attributes
        if given_name:
            request.given_name = given_name
        if surname:
            request.surname = surname
        if org_unit:
            request.organizational_unit = org_unit

        # Collect subject alternative names
        subject_alt_name = set()
        if email_address:
            subject_alt_name.add("email:%s" % email_address)
        if ip_address:
            subject_alt_name.add("IP:%s" % ip_address)
        if dns:
            subject_alt_name.add("DNS:%s" % dns)

        # Set extensions
        extensions = []
        if key_usage:
            extensions.append(("keyUsage", key_usage, True))
        if extended_key_usage:
            extensions.append(("extendedKeyUsage", extended_key_usage, False))
        if subject_alt_name:
            extensions.append(("subjectAltName", ", ".join(subject_alt_name), False))
        request.set_extensions(extensions)

        # Dump CSR
        os.umask(0o022)
        with open(request_path + ".part", "w") as fh:
            fh.write(request.dump())

        click.echo("Writing private key to: %s" % key_path)
        os.rename(key_partial, key_path)
        click.echo("Writing certificate signing request to: %s" % request_path)
        os.rename(request_path + ".part", request_path)

    # We have CSR now, save the paths to client.conf so we could:
    # Update CRL, renew certificate, maybe something extra?

    if not os.path.exists("/etc/certidude"):
        os.makedirs("/etc/certidude")

    clients = ConfigParser()
    if os.path.exists("/etc/certidude/client.conf"):
        clients.readfp(open("/etc/certidude/client.conf"))

    if clients.has_section(server):
        click.echo("Section %s already exists in /etc/certidude/client.conf, not reconfiguring" % server)
    else:
        clients.add_section(server)
        clients.set(server, "trigger", "interface up")
        clients.set(server, "key_path", key_path)
        clients.set(server, "request_path", request_path)
        clients.set(server, "certificate_path", certificate_path)
        clients.set(server, "authority_path", authority_path)
        clients.set(server, "key_path", key_path)
        clients.set(server, "revocations_path", revocations_path)
        clients.write(open("/etc/certidude/client.conf", "w"))
        click.echo("Section %s added to /etc/certidude/client.conf" % repr(server))

    if os.path.exists(certificate_path):
        click.echo("Found certificate: %s" % certificate_path)
        # TODO: Check certificate validity, download CRL?
        return

    click.echo("Submitting to %s, waiting for response..." % request_url)
    submission = requests.post(request_url,
        data=open(request_path),
        headers={"Content-Type": "application/pkcs10", "Accept": "application/x-x509-user-cert,application/x-pem-file"})

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
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, submission.text)
    except crypto.Error:
        raise ValueError("Failed to parse PEM: %s" % submission.text)

    os.umask(0o022)
    with open(certificate_path + ".part", "w") as fh:
        # Dump certificate
        fh.write(submission.text)

        # Bundle CA certificate, necessary for nginx
        if bundle:
            with open(authority_path) as ch:
                fh.write(ch.read())

    click.echo("Writing certificate to: %s" % certificate_path)
    os.rename(certificate_path + ".part", certificate_path)

    # TODO: Validate fetched certificate against CA
    # TODO: Check that recevied certificate CN and pubkey match
    # TODO: Check file permissions
