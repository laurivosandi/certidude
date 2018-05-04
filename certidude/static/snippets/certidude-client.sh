pip3 install git+https://github.com/laurivosandi/certidude/
mkdir -p /etc/certidude/{client.conf.d,services.conf.d}
cat << EOF > /etc/certidude/client.conf.d/{{ authority_name }}.conf
[{{ authority_name }}]
trigger = interface up
common name = $HOSTNAME
system wide = true
EOF

cat << EOF > /etc/certidude/services.conf.d/{{ authority_name }}.conf
{% for router in session.service.routers %}{% if "ikev2" in session.service.protocols %}
[IPSec to {{ router }}]
authority = {{ authority_name }}
service = network-manager/strongswan
remote = {{ router }}
{% endif %}{% if "openvpn" in session.service.protocols %}
[OpenVPN to {{ router }}]
authority = {{ authority_name }}
service = network-manager/openvpn
remote = {{ router }}
{% endif %}{% endfor %}
EOF

certidude enroll

