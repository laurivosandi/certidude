#!/bin/sh
cat << EOF | curl -s -X POST -d @- -H "X-EventSource-Event: $PLUTO_VERB" http://ca.example.com/pub/?id=CA-channel-identifier-goes-here
{"address": "$(echo $PLUTO_PEER_CLIENT  | sed 's/\/32$//')", "peer": "$PLUTO_PEER", "identity": "$PLUTO_PEER_ID", "routed_subnet": "$PLUTO_MY_CLIENT"}
EOF
