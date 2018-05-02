test -e /sbin/uci && NAME=$(nslookup $(uci get network.wan.ipaddr) |  grep "name =" | head -n1 | cut -d "=" -f 2 | xargs)
test -e /bin/hostname && NAME=$(hostname -f)
test -n "$NAME" || NAME=$(cat /proc/sys/kernel/hostname)

{% include "snippets/update-trust.sh" %}

{% include "snippets/request-common.sh" %}

curl -f -L -H "Content-type: application/pkcs10" \
    --cacert /etc/certidude/authority/{{ authority_name }}/ca_cert.pem \
    --data-binary @/etc/certidude/authority/{{ authority_name }}/host_req.pem \
    -o /etc/certidude/authority/{{ authority_name }}/host_cert.pem \
    'https://{{ authority_name }}:8443/api/request/?wait=yes'
