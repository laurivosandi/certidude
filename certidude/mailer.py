
import click
import os
import smtplib
from certidude.user import User
from markdown import markdown
from jinja2 import Environment, PackageLoader
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from urllib.parse import urlparse

env = Environment(loader=PackageLoader("certidude", "templates/mail"))

def send(template, to=None, secondary=None, include_admins=True, attachments=(), **context):
    from certidude import authority, config

    recipients = ()
    if include_admins:
        recipients = tuple(User.objects.filter_admins())
    if to:
        recipients = (to,) + recipients
    if secondary:
        recipients = (secondary,) + recipients


    click.echo("Sending e-mail %s to %s" % (template, recipients))

    subject, text = env.get_template(template).render(context).split("\n\n", 1)
    html = markdown(text)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "%s <%s>" % (config.MAILER_NAME, config.MAILER_ADDRESS)
    msg["To"] = ", ".join([str(j) for j in recipients])

    part1 = MIMEText(text, "plain", "utf-8")
    part2 = MIMEText(html, "html", "utf-8")

    msg.attach(part1)
    msg.attach(part2)

    for attachment, content_type, suggested_filename in attachments:
        part = MIMEBase(*content_type.split("/"))
        part.add_header('Content-Disposition', 'attachment', filename=suggested_filename)
        part.set_payload(attachment)
        msg.attach(part)

    if config.MAILER_ADDRESS:
        click.echo("Sending to: %s" % msg["to"])
        conn = smtplib.SMTP("localhost")
        conn.sendmail(config.MAILER_ADDRESS, [str(u) for u in recipients], msg.as_string())
