
import click
import json
import urllib.request
from certidude import config


def publish(event_type, event_data):
    """
    Publish event on push server
    """
    if not isinstance(event_data, str):
        from certidude.decorators import MyEncoder
        event_data = json.dumps(event_data, cls=MyEncoder)

    url = config.PUSH_PUBLISH % config.PUSH_TOKEN
    click.echo("Posting event %s %s at %s, waiting for response..." % (repr(event_type), repr(event_data), repr(url)))
    notification = urllib.request.Request(
        url,
        event_data.encode("utf-8"),
        {"Event-ID": b"TODO", "Event-Type":event_type.encode("ascii")})
    notification.add_header("User-Agent", "Certidude API")

    try:
        response = urllib.request.urlopen(notification)
        body = response.read()
    except urllib.error.HTTPError as err:
        if err.code == 404:
            print("No subscribers on the channel")
        else:
            raise
    else:
        print("Push server returned:", response.code, body)
    response.close()



