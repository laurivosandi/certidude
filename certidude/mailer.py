
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
    if not config.MAILER_ADDRESS:
        # Mailbox disabled, don't send e-mail
        return

    recipients = u", ".join([unicode(j) for j in User.objects.filter_admins()])

    if to:
        recipients = to + u", " + recipients

    click.echo("Sending e-mail %s to %s" % (template, recipients))

    subject, text = env.get_template(template).render(context).split("\n\n", 1)
    html = markdown(text)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "%s <%s>" % (config.MAILER_NAME, config.MAILER_ADDRESS)
    msg["To"] = recipients

    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    msg.attach(part1)
    msg.attach(part2)

    for attachment, content_type, suggested_filename in attachments:
        part = MIMEBase(*content_type.split("/"))
        part.add_header('Content-Disposition', 'attachment', filename=suggested_filename)
        part.set_payload(attachment)
        msg.attach(part)

    conn = smtplib.SMTP("localhost")
    conn.sendmail(config.MAILER_ADDRESS, recipients, msg.as_string())
