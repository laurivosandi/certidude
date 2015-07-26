
import os
import smtplib
from time import sleep
from jinja2 import Environment, PackageLoader
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

class Mailer(object):
    def __init__(self, url):
        scheme, netloc, path, params, query, fragment = urlparse(url)
        scheme = scheme.lower()

        if path:
            raise ValueError("Path for URL not supported")
        if params:
            raise ValueError("Parameters for URL not supported")
        if query:
            raise ValueError("Query for URL not supported")
        if fragment:
            raise ValueError("Fragment for URL not supported")


        self.username = None
        self.password = ""

        if scheme == "smtp":
            self.secure = False
            self.port = 25
        elif scheme == "smtps":
            self.secure = True
            self.port = 465
        else:
            raise ValueError("Unknown scheme '%s', currently SMTP and SMTPS are only supported" % scheme)

        if "@" in netloc:
            credentials, netloc = netloc.split("@")

            if ":" in credentials:
                self.username, self.password = credentials.split(":")
            else:
                self.username = credentials

        if ":" in netloc:
            self.server, port_str = netloc.split(":")
            self.port = int(port_str)
        else:
            self.server = netloc

        self.env = Environment(loader=PackageLoader("certidude", "email_templates"))
        self.conn = None

    def reconnect(self):
        # Gmail employs some sort of IPS
        # https://accounts.google.com/DisplayUnlockCaptcha
        print("Connecting to:", self.server, self.port)
        self.conn = smtplib.SMTP(self.server, self.port)
        if self.secure:
            self.conn.starttls()
        if self.username and self.password:
            self.conn.login(self.username, self.password)

    def enqueue(self, sender, recipients, subject, template, **context):
        self.send(sender, recipients, subject, template, **context)


    def send(self, sender, recipients, subject, template, **context):

        recipients = [j for j in recipients if j]

        if not recipients:
            print("No recipients to send e-mail to!")
            return
        print("Sending e-mail to:", recipients, "body follows:")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)

        text = self.env.get_template(template + ".txt").render(context)
        html = self.env.get_template(template + ".html").render(context)

        print(text)

        part1 = MIMEText(text, "plain")
        part2 = MIMEText(html, "html")

        msg.attach(part1)
        msg.attach(part2)

        backoff = 1
        while True:
            try:
                if not self.conn:
                    self.reconnect()
                self.conn.sendmail(sender, recipients, msg.as_string())
                return
            except smtplib.SMTPServerDisconnected:
                print("Connection to %s unexpectedly closed, probably TCP timeout, backing off for %d second" % (self.server, backoff))
                self.reconnect()
                backoff = backoff * 2
                sleep(backoff)
