# Use fully qualified name
test -e /sbin/uci && NAME=$(nslookup $(uci get network.wan.ipaddr) |  grep "name =" | head -n1 | cut -d "=" -f 2 | xargs)
test -e /bin/hostname && NAME=$(hostname -f)
test -n "$NAME" || NAME=$(cat /proc/sys/kernel/hostname)

{% include "snippets/request-common.sh" %}
{% include "snippets/submit-request-wait.sh" %}
