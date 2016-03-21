
import click
import os
import requests
from certidude import errors
from certidude.wrappers import Certificate, Request
from OpenSSL import crypto

def certidude_request_certificate(url, key_path, request_path, certificate_path, authority_path, common_name, org_unit=None, email_address=None, given_name=None, surname=None, autosign=False, wait=False, key_usage=None, extended_key_usage=None, ip_address=None, dns=None, bundle=False):
    """
    Exchange CSR for certificate using Certidude HTTP API server
    """

    # Set up URL-s
    request_params = set()
    if autosign:
        request_params.add("autosign=true")
    if wait:
        request_params.add("wait=forever")

    # Expand ca.example.com to http://ca.example.com/api/
    if not url.endswith("/"):
        url += "/api/"
    if "//" not in url:
        url = "http://" + url

    authority_url = url + "certificate"
    request_url = url + "request"

    if request_params:
        request_url = request_url + "?" + "&".join(request_params)

    if os.path.exists(certificate_path):
        click.echo("Found certificate: %s" % certificate_path)
        # TODO: Check certificate validity, download CRL?
        return

    if os.path.exists(authority_path):
        click.echo("Found CA certificate in: %s" % authority_path)
    else:
        click.echo("Attempting to fetch CA certificate from %s" % authority_url)

        try:
            r = requests.get(authority_url,
                    headers={"Accept": "application/x-x509-ca-cert,application/x-pem-file"})
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, r.text)
        except crypto.Error:
            raise ValueError("Failed to parse PEM: %s" % r.text)
        with open(authority_path + ".part", "w") as oh:
            oh.write(r.text)
        click.echo("Writing CA certificate to: %s" % authority_path)
        os.rename(authority_path + ".part", authority_path)

    try:
        request = Request(open(request_path))
        click.echo("Found signing request: %s" % request_path)
    except EnvironmentError:

        # Construct private key
        click.echo("Generating 4096-bit RSA key...")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        # Dump private key
        os.umask(0o077)
        with open(key_path + ".part", "wb") as fh:
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
        os.rename(key_path + ".part", key_path)
        click.echo("Writing certificate signing request to: %s" % request_path)
        os.rename(request_path + ".part", request_path)


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
