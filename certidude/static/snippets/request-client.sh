test -e /sbin/uci && NAME=$(uci get system.@system[0].hostname)
test -e /bin/hostname && NAME=$(hostname)
test -n "$NAME" || NAME=$(cat /proc/sys/kernel/hostname)

{% include "snippets/update-trust.sh" %}

{% include "snippets/request-common.sh" %}

curl -f -L -H "Content-type: application/pkcs10" \
--data-binary @/etc/certidude/authority/{{ authority_name }}/host_req.pem \
-o /etc/certidude/authority/{{ authority_name }}/host_cert.pem \
'http://{{ authority_name }}/api/request/?wait=yes&autosign=yes'



