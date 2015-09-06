"""
    certidude.wsgi
    ~~~~~~~~~~~~~~

    Certidude web app factory for WSGI-compatible web servers
"""
import os
from certidude.api import certidude_app

# TODO: set up /run/certidude/api paths and permissions
assert os.getenv("PUSH_SUBSCRIBE"), "Please set PUSH_SUBSCRIBE to your web server's subscription URL"
assert os.getenv("PUSH_PUBLISH"), "Please set PUSH_PUBLISH to your web server's publishing URL"

app = certidude_app()
