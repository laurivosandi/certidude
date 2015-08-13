
import click
import logging
import netifaces
import os
import urllib.request
from certidude.wrappers import Certificate, Request
from certidude.signer import SignServer
from OpenSSL import crypto

def expand_paths():
    """
    Prefix '..._path' keyword arguments of target function with 'directory' keyword argument
    and create the directory if necessary

    TODO: Move to separate file
    """
    def wrapper(func):
        def wrapped(**arguments):
            d = arguments.get("directory")
            for key, value in arguments.items():
                if key.endswith("_path"):
                    if d:
                        value = os.path.join(d, value)
                    value = os.path.realpath(value)
                    parent = os.path.dirname(value)
                    if not os.path.exists(parent):
                        click.echo("Making directory %s for %s" % (repr(parent), repr(key)))
                        os.makedirs(parent)
                    elif not os.path.isdir(parent):
                        raise Exception("Path %s is not directory!" % parent)
                    arguments[key] = value
            return func(**arguments)
        return wrapped
    return wrapper


def certidude_request_certificate(url, key_path, request_path, certificate_path, authority_path, common_name, org_unit, email_address=None, given_name=None, surname=None, autosign=False, wait=False, key_usage=None, extended_key_usage=None, ip_address=None, dns=None):
    """
    Exchange CSR for certificate using Certidude HTTP API server
    """

    # Set up URL-s
    request_params = set()
    if autosign:
        request_params.add("autosign=yes")
    if wait:
        request_params.add("wait=forever")

    if not url.endswith("/"):
        url = url + "/"

    authority_url = url + "certificate"
    request_url = url + "request"

    if request_params:
        request_url = request_url + "?" + "&".join(request_params)

    if os.path.exists(authority_path):
        click.echo("Found CA certificate in: %s" % authority_path)
    else:
        if authority_url:
            click.echo("Attempting to fetch CA certificate from %s" % authority_url)
            try:
                with urllib.request.urlopen(authority_url) as fh:
                    buf = fh.read()
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
                    except crypto.Error:
                        raise ValueError("Failed to parse PEM: %s" % buf)
                    with open(authority_path + ".part", "wb") as oh:
                        oh.write(buf)
                    click.echo("Writing CA certificate to: %s" % authority_path)
                    os.rename(authority_path + ".part", authority_path)
            except urllib.error.HTTPError as e:
                click.echo("Failed to fetch CA certificate, server responded with: %d %s" % (e.code, e.reason), err=True)
                return 1
        else:
            raise FileNotFoundError("CA certificate not found and no URL specified")

    try:
        certificate = Certificate(open(certificate_path))
        click.echo("Found certificate: %s" % certificate_path)
    except FileNotFoundError:
        try:
            request = Request(open(request_path))
            click.echo("Found signing request: %s" % request_path)
        except FileNotFoundError:

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
            request = Request(csr)

            # Set subject attributes
            request.common_name = common_name
            if given_name:
                request.given_name = given_name
            if surname:
                request.surname = surname
            if org_unit:
                request.organizational_unit = org_unit

            # Collect subject alternative names
            subject_alt_name = set()
            if email_address:
                subject_alt_name.add("email:" + email_address)
            if ip_address:
                subject_alt_name.add("IP:" + ip_address)
            if dns:
                subject_alt_name.add("DNS:" + dns)

            # Set extensions
            extensions = []
            if key_usage:
                extensions.append(("keyUsage", key_usage, True))
            if extended_key_usage:
                extensions.append(("extendedKeyUsage", extended_key_usage, True))
            if subject_alt_name:
                extensions.append(("subjectAltName", ", ".join(subject_alt_name), True))
            request.set_extensions(extensions)

            # Dump CSR
            os.umask(0o022)
            with open(request_path + ".part", "w") as fh:
                fh.write(request.dump())

            click.echo("Writing private key to: %s" % key_path)
            os.rename(key_path + ".part", key_path)
            click.echo("Writing certificate signing request to: %s" % request_path)
            os.rename(request_path + ".part", request_path)


        with open(request_path, "rb") as fh:
            buf = fh.read()
            submission = urllib.request.Request(request_url, buf)
            submission.add_header("User-Agent", "Certidude")
            submission.add_header("Content-Type", "application/pkcs10")

            click.echo("Submitting to %s, waiting for response..." % request_url)
            try:
                response = urllib.request.urlopen(submission)
                buf = response.read()
                if response.code == 202:
                    click.echo("No waiting was requested and server responded with 202 Accepted, run this command again once the certificate is signed")
                    return 1
                assert buf, "Server responded with no body, status code %d" % response.code
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, buf)
            except crypto.Error:
                raise ValueError("Failed to parse PEM: %s" % buf)
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    click.echo("Different signing request with same CN is already present on server, server refuses to overwrite", err=True)
                    return 2
                else:
                    click.echo("Failed to fetch certificate, server responded with: %d %s" % (e.code, e.reason), err=True)
                    return 3
            else:
                if response.code == 202:
                    click.echo("Server stored the request for processing (202 Accepted), but waiting was not requested, hence quitting for now", err=True)
                    return 254

            os.umask(0o022)
            with open(certificate_path + ".part", "wb") as gh:
                gh.write(buf)

            click.echo("Writing certificate to: %s" % certificate_path)
            os.rename(certificate_path + ".part", certificate_path)

    # TODO: Validate fetched certificate against CA
    # TODO: Check that recevied certificate CN and pubkey match
    # TODO: Check file permissions
