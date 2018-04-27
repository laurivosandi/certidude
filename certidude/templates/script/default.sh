#!/bin/sh

{% if named_tags or other_tags %}
# Tags:
{% for key, value in named_tags.items() %}
# {{ key }} -> {{ value }}
{% endfor %}
{% for tag in other_tags %}
# {{ tag }}
{% endfor %}
{% else %}
# No tags
{% endif %}

ARGS="kernel=$(uname -sr)&\
cpu=$(cat /proc/cpuinfo  | grep '^model name' | head -n1 | cut -d ":" -f2 | xargs)&\
$(for j in /sys/class/net/[we]*[a-z][0-9]; do echo -en if.$(basename $j).ether=$(cat $j/address)\&; done)"

if [ -e /etc/openwrt_release ]; then
  . /etc/openwrt_release
  ARGS="$ARGS&dist=$DISTRIB_ID $DISTRIB_RELEASE"
else
  ARGS="$ARGS&dist=$(lsb_release -si) $(lsb_release -sr)"
fi

if [ -e /sys/class/dmi ]; then
  ARGS="$ARGS&dmi.product_name=$(cat /sys/class/dmi/id/product_name)&dmi.product_serial=$(cat /sys/class/dmi/id/product_serial)"
  ARGS="$ARGS&&mem=$(dmidecode -t 17 | grep Size | cut -d ":" -f 2 | cut -d " " -f 2 | paste -sd+ | bc) MB"
else
  ARGS="$ARGS&dmi.product_name=$(cat /proc/cpuinfo  | grep '^machine' | head -n 1 | cut -d ":"   -f 2 | xargs)"
  ARGS="$ARGS&mem=$(echo $(cat /proc/meminfo  | grep MemTotal | cut -d ":" -f 2 | xargs | cut -d " " -f 1)/1000+1 | bc) MB"
fi

# Submit some stats to CA
curl https://{{ authority_name }}:8443/api/signed/{{ common_name }}/attr \
--cacert /etc/certidude/authority/{{ authority_name }}/ca_cert.pem \
--key /etc/certidude/authority/{{ authority_name }}/host_key.pem \
--cert /etc/certidude/authority/{{ authority_name }}/host_cert.pem \
-X POST \-d "$ARGS"
