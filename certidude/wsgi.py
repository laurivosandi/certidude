"""
    certidude.wsgi
    ~~~~~~~~~~~~~~

    Certidude web app factory for WSGI-compatible web servers
"""
import os
from certidude.api import certidude_app

# TODO: set up /run/certidude/api paths and permissions

app = certidude_app()
