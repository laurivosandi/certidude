# Use fully qualified name
test -e /sbin/uci && NAME=$(nslookup $(uci get network.wan.ipaddr) |  grep "name =" | head -n1 | cut -d "=" -f 2 | xargs)
test -e /bin/hostname && NAME=$(hostname -f)
test -n "$NAME" || NAME=$(cat /proc/sys/kernel/hostname)

{% include "snippets/request-common.sh" %}
# Submit CSR and save signed certificate
curl --cert-status -f -L -H "Content-type: application/pkcs10" \
    --cacert /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem \
    --data-binary @/etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem \
    -o /etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem \
    'https://{{ session.authority.hostname }}:8443/api/request/?wait=yes'
