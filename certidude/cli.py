#!/usr/bin/python3
# coding: utf-8

import socket
import click
import os
import time
import os
import re
from datetime import datetime
from OpenSSL import crypto
from certidude.wrappers import CertificateAuthorityConfig, \
    CertificateAuthority, SerialCounter, Certificate, subject2dn

# Big fat warning:
# m2crypto overflows around 2030 because on 32-bit systems
# m2crypto does not support hardware engine support (?)
# m2crypto CRL object is pretty much useless
# pyopenssl has no straight-forward methods for getting RSA key modulus

# http://www.mad-hacking.net/documentation/linux/security/ssl-tls/creating-ca.xml

config = CertificateAuthorityConfig("/etc/ssl/openssl.cnf")

NOW = datetime.utcnow().replace(tzinfo=None)


@click.command("create", help="Set up Certificate Authority in a directory")
@click.option("--parent", "-p", help="Parent CA, none by default")
@click.option("--common-name", "-cn", default=socket.gethostname(), help="Common name, hostname by default")
@click.option("--country", "-c", default="ee", help="Country, Estonia by default")
@click.option("--state", "-s", default="Harjumaa", help="State or country, Harjumaa by default")
@click.option("--locality", "-l", default="Tallinn", help="City or locality, Tallinn by default")
@click.option("--lifetime", default=20, help="Lifetime in years")
@click.option("--organization", "-o", default="Example LLC", help="Company or organization name")
@click.option("--organizational-unit", "-ou", default="Certification Department")
@click.option("--crl-age", default=1, help="CRL expiration age, 1 day by default")
@click.option("--pkcs11", default=False, is_flag=True, help="Use PKCS#11 token instead of files")
@click.argument("directory")
def ca_create(parent, country, state, locality, organization, organizational_unit, common_name, directory, crl_age, lifetime, pkcs11):
    click.echo("Generating 4096-bit RSA key...")
    
    if pkcs11:
        raise NotImplementedError("Hardware token support not yet implemented!")
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)
    slug = os.path.basename(directory)
    crl_distribution_points = "URI:http://%s/api/%s/revoked/" % (common_name, slug)
    ca = crypto.X509()
    ca.set_version(3)
    ca.set_serial_number(1)
    ca.get_subject().CN = common_name
    ca.get_subject().C = country
    ca.get_subject().ST = state
    ca.get_subject().L = locality
    ca.get_subject().O = organization
    ca.get_subject().OU = organizational_unit
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(lifetime * 365 * 24 * 60 * 60)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions([
        crypto.X509Extension(
            b"basicConstraints",
            True,
            b"CA:TRUE, pathlen:0"),
        crypto.X509Extension(
            b"keyUsage",
            True,
            b"keyCertSign, cRLSign"),
        crypto.X509Extension(
            b"subjectKeyIdentifier",
            False,
            b"hash",
            subject = ca),
        crypto.X509Extension(
            b"crlDistributionPoints",
            False,
            crl_distribution_points.encode("ascii"))
    ])

    click.echo("Signing %s..." % subject2dn(ca.get_subject()))
    ca.sign(key, "sha1")
    
    if not os.path.exists(directory):
        os.makedirs(directory)
    for subdir in ("signed", "requests", "revoked"):
        if not os.path.exists(os.path.join(directory, subdir)):
            os.mkdir(os.path.join(directory, subdir))
    with open(os.path.join(directory, "ca_key.pem"), "wb") as fh:
        fh.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    with open(os.path.join(directory, "ca_crt.pem"), "wb") as fh:
        fh.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    with open(os.path.join(directory, "ca_crl.pem"), "wb") as fh:
        crl = crypto.CRL()
        fh.write(crl.export(ca, key, days=crl_age))
    with open(os.path.join(directory, "serial"), "w") as fh:
        fh.write("1")
        

    click.echo()
    click.echo("Add following to your /etc/ssl/openssl.cnf:")
    click.echo()
    click.echo("[CA_%s]" % slug)
    click.echo("dir = %s" % directory)
    click.echo("private_key = $dir/ca_key.pem")
    click.echo("certificate = $dir/ca_crt.pem")
    click.echo("new_certs_dir = $dir/requests/")
    click.echo("revoked_certs_dir = $dir/revoked/")
    click.echo("certs = $dir/signed/")
    click.echo("crl = $dir/ca_crl.pem")
    click.echo("serial = $dir/serial")
    click.echo("crlDistributionPoints = %s" % crl_distribution_points)

    click.echo()
    click.echo("Use following commands to inspect the newly created files:")
    click.echo()
    click.echo("  openssl crl -inform PEM -text -noout -in %s" % os.path.join(directory, "ca_crl.pem"))
    click.echo("  openssl x509 -in %s -text -noout" % os.path.join(directory, "ca_crt.pem"))
    click.echo("  openssl rsa -in %s -check" % os.path.join(directory, "ca_key.pem"))
    click.echo()
    click.echo("Use following command to serve CA read-only:")
    click.echo()
    click.echo("  certidude serve")
    
@click.command("list", help="List Certificate Authorities")
def ca_list():
    for ca in config.all_authorities():
        click.echo("Certificate authority '%s'" % ca.certificate.get_dn())

        if ca.certificate.not_before < NOW and ca.certificate.not_after > NOW:
            click.echo("  ✓ Certificate valid %s" % (ca.certificate.not_after - NOW))
        elif NOW > ca.certificate.not_after:
            click.echo("  ✗ Certificate expired")
        else:
            click.echo("  ✗ Certificate authority not valid yet")
        
        if os.path.exists(ca.private_key):
            click.echo("  ✓ Private key %s okay" % ca.private_key)
        else:
            click.echo("  ✗ Private key %s does not exist" % ca.private_key)
            
        if os.path.isdir(ca.signed_dir):
            click.echo("  ✓ Signed certificates directory %s okay" % ca.signed_dir)
        else:
            click.echo("  ✗ Signed certificates directory %s okay" % ca.signed_dir)
            
        click.echo("  Revoked certificates directory: %s" % ca.revoked_dir)
        click.echo("  Revocation list: %s" % ca.revocation_list)

        click.echo()

@click.command("list", help="List Certificate Authorities")
@click.argument("ca")
@config.pop_certificate_authority()
def cert_list(ca):
    mapping = {}
    
    click.echo("Listing certificates for: %s" % ca.certificate.subject.CN)

    for serial, reason, timestamp in ca.get_revoked():
        mapping[serial] = None, reason

    for certificate in ca.get_signed():
        mapping[certificate.serial] = certificate, None
        
    for serial, (certificate, reason) in sorted(mapping.items(), key=lambda j:j[0]):            
        if not reason:
            click.echo("  %03d. %s %s" % (serial, certificate.subject.CN, (certificate.not_after-NOW)))
        else:
            click.echo("  %03d. Revoked due to: %s" % (serial, reason))

    for request in ca.get_requests():
        click.echo("  ⌛  %s" % request.subject.CN)

@click.command("serve", help="Run built-in HTTP server")
@click.option("-u", "--user", default=None, help="Run as user")
@click.option("-p", "--port", default=80, help="Listen port")
@click.option("-l", "--listen", default="0.0.0.0", help="Listen address")
@click.option("-s", "--enable-signature", default=False, is_flag=True, help="Allow signing operations with private key of CA")
def serve(user, port, listen, enable_signature):
    click.echo("Serving API at %s:%d" % (listen, port))
    import pwd
    import falcon
    from wsgiref.simple_server import make_server, WSGIServer
    from socketserver import ThreadingMixIn
    from certidude.api import CertificateAuthorityResource, \
        RequestDetailResource, RequestListResource, \
        SignedCertificateDetailResource, SignedCertificateListResource

    class ThreadingWSGIServer(ThreadingMixIn, WSGIServer): 
        pass
    click.echo("Listening on %s:%d" % (listen, port))
    
    app = falcon.API()
    app.add_route("/api/{ca}/signed/{cn}/", SignedCertificateDetailResource(config))
    app.add_route("/api/{ca}/signed/", SignedCertificateListResource(config))
    app.add_route("/api/{ca}/request/{cn}/", RequestDetailResource(config))
    app.add_route("/api/{ca}/request/", RequestListResource(config))
    app.add_route("/api/{ca}/", CertificateAuthorityResource(config))
    httpd = make_server(listen, port, app, ThreadingWSGIServer)
    if user:
        _, _, uid, gid, gecos, root, shell = pwd.getpwnam(user)
        if uid == 0:
            click.echo("Please specify unprivileged user")
            exit(254)
        click.echo("Switching to user %s (uid=%d, gid=%d)" % (user, uid, gid))
        os.setgid(gid)
        os.setuid(uid)
    elif os.getuid() == 0:
        click.echo("Warning: running as root, this is not reccommended!")
    httpd.serve_forever()

@click.group(help="Certificate Authority management")
def ca(): pass

@click.group(help="Certificate management")
def cert(): pass

cert.add_command(cert_list)
ca.add_command(ca_create)
ca.add_command(ca_list)

@click.group()
def entry_point(): pass

entry_point.add_command(ca)
entry_point.add_command(cert)
entry_point.add_command(serve)
