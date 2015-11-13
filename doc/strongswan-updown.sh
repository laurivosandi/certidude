#!/bin/sh
cat << EOF | curl -X POST -d @- -H "Event-Type: $PLUTO_VERB" http://ca.example.com/pub/?id=CA-channel-identifier-goes-here
{"address": "$PLUTO_PEER_SOURCEIP","peer": "$PLUTO_PEER","identity": "$PLUTO_PEER_ID","routed_subnet": "$PLUTO_MY_CLIENT"}
EOF
