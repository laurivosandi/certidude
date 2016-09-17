
import click
import os
import smtplib
from certidude.user import User
from markdown import markdown
from jinja2 import Environment, PackageLoader
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from urlparse import urlparse

env = Environment(loader=PackageLoader("certidude", "templates/mail"))

def send(template, to=None, attachments=(), **context):
    from certidude import authority, config
    if not config.OUTBOX:
        # Mailbox disabled, don't send e-mail
        return

    recipients = u", ".join([unicode(j) for j in User.objects.filter_admins()])

    if to:
        recipients = to + u", " + recipients

    click.echo("Sending e-mail %s to %s" % (template, recipients))

    scheme, netloc, path, params, query, fragment = urlparse(config.OUTBOX)
    scheme = scheme.lower()

    if path:
        raise ValueError("Path for URL not supported")
    if params:
        raise ValueError("Parameters for URL not supported")
    if query:
        raise ValueError("Query for URL not supported")
    if fragment:
        raise ValueError("Fragment for URL not supported")


    username = None
    password = ""

    if scheme == "smtp":
        secure = False
        port = 25
    elif scheme == "smtps":
        secure = True
        port = 465
    else:
        raise ValueError("Unknown scheme '%s', currently SMTP and SMTPS are only supported" % scheme)

    if "@" in netloc:
        credentials, netloc = netloc.split("@")

        if ":" in credentials:
            username, password = credentials.split(":")
        else:
            username = credentials

    if ":" in netloc:
        server, port_str = netloc.split(":")
        port = int(port_str)
    else:
        server = netloc


    subject, text = env.get_template(template).render(context).split("\n\n", 1)
    html = markdown(text)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = authority.certificate.email_address
    msg["To"] = recipients

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    msg.attach(part1)
    msg.attach(part2)

    for attachment in attachments:
        part = MIMEBase(*attachment.content_type.split("/"))
        part.add_header('Content-Disposition', 'attachment', filename=attachment.suggested_filename)
        part.set_payload(attachment.dump())
        msg.attach(part)

    # Gmail employs some sort of IPS
    # https://accounts.google.com/DisplayUnlockCaptcha
    conn = smtplib.SMTP(server, port)
    if secure:
        conn.starttls()
    if username and password:
        conn.login(username, password)

    conn.sendmail(authority.certificate.email_address, recipients, msg.as_string())
