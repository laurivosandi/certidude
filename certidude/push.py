
import click
import json
import requests
from certidude import config


def publish(event_type, event_data):
    """
    Publish event on push server
    """
    if not isinstance(event_data, str):
        from certidude.decorators import MyEncoder
        event_data = json.dumps(event_data, cls=MyEncoder)

    notification = requests.post(
        config.PUSH_PUBLISH % config.PUSH_TOKEN,
        data=event_data,
        headers={"X-EventSource-Event": event_type, "User-Agent": "Certidude API"})


