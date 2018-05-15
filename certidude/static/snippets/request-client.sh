# Use short hostname as common name
test -e /sbin/uci && NAME=$(uci get system.@system[0].hostname)
test -e /bin/hostname && NAME=$(hostname)
test -n "$NAME" || NAME=$(cat /proc/sys/kernel/hostname)

{% include "snippets/request-common.sh" %}
# Submit CSR and save signed certificate
curl --cert-status -f -L -H "Content-type: application/pkcs10" \
  --data-binary @/etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem \
  -o /etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem \
  'http://{{ session.authority.hostname }}/api/request/?wait=yes&autosign=yes'
