# Create VPN gateway up/down script for reporting client IP addresses to CA
cat <<\EOF > /etc/certidude/authority/{{ session.authority.hostname }}/updown
#!/bin/sh

CURL="curl -m 3 -f --key /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem --cert /etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem --cacert /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem https://{{ session.authority.hostname }}:8443/api/lease/"

case $PLUTO_VERB in
    up-client) $CURL --data-urlencode "outer_address=$PLUTO_PEER" --data-urlencode "inner_address=$PLUTO_PEER_SOURCEIP" --data-urlencode "client=$PLUTO_PEER_ID" ;;
    *) ;;
esac

case $script_type in
    client-connect) $CURL --data-urlencode client=$X509_0_CN --data-urlencode serial=$tls_serial_0 --data-urlencode outer_address=$untrusted_ip --data-urlencode inner_address=$ifconfig_pool_remote_ip ;;
    *) ;;
esac
EOF

chmod +x /etc/certidude/authority/{{ session.authority.hostname }}/updown

