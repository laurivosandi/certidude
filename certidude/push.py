
import click
import json
import logging
import requests
from datetime import datetime
from certidude import config


def publish(event_type, event_data):
    """
    Publish event on push server
    """
    if not isinstance(event_data, basestring):
        from certidude.decorators import MyEncoder
        event_data = json.dumps(event_data, cls=MyEncoder)

    url = config.PUSH_PUBLISH % config.PUSH_TOKEN
    click.echo("Publishing %s event %s on %s" % (event_type, event_data, url))

    try:
        notification = requests.post(
            url,
            data=event_data,
            headers={"X-EventSource-Event": event_type, "User-Agent": "Certidude API"})
    except requests.exceptions.ConnectionError:
        click.echo("Failed to submit event to push server: %s" % repr(event_data))

class PushLogHandler(logging.Handler):
    """
    To be used with Python log handling framework for publishing log entries
    """
    def emit(self, record):
        from certidude.push import publish
        publish("log-entry", dict(
            created = datetime.fromtimestamp(record.created),
            message = record.msg % record.args,
            severity = record.levelname.lower()))

