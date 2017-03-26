
import click
import json
import logging
import requests
from datetime import datetime
from certidude import config


def publish(event_type, event_data):
    """
    Publish event on nchan EventSource publisher
    """
    assert event_type, "No event type specified"
    assert event_data, "No event data specified"
    if not config.EVENT_SOURCE_PUBLISH:
        # Push server disabled
        return

    if not isinstance(event_data, basestring):
        from certidude.decorators import MyEncoder
        event_data = json.dumps(event_data, cls=MyEncoder)

    url = config.EVENT_SOURCE_PUBLISH % config.EVENT_SOURCE_TOKEN
    click.echo("Publishing %s event '%s' on %s" % (event_type, event_data, url))

    try:
        notification = requests.post(
            url,
            data=event_data,
            headers={"X-EventSource-Event": event_type, "User-Agent": "Certidude API"})
        if notification.status_code == requests.codes.created:
            pass # Sent to client
        elif notification.status_code == requests.codes.accepted:
            pass # Buffered in nchan
        else:
            click.echo("Failed to submit event to push server, server responded %d" % (
                notification.status_code))
    except requests.exceptions.ConnectionError:
        click.echo("Failed to submit event to push server, connection error")


class EventSourceLogHandler(logging.Handler):
    """
    To be used with Python log handling framework for publishing log entries
    """
    def emit(self, record):
        publish("log-entry", dict(
            created = datetime.utcfromtimestamp(record.created),
            message = record.msg % record.args,
            severity = record.levelname.lower()))

