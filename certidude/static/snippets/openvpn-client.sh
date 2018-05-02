# Install packages on Ubuntu & Fedora
which apt && apt install openvpn
which dnf && dnf install openvpn

cat > /etc/openvpn/{{ authority_name }}.conf << EOF
client
nobind
{% for router in session.service.routers %}
remote {{ router }} 1194 udp
remote {{ router }} 443 tcp-client
{% endfor %}
tls-version-min 1.2
tls-cipher TLS-{% if session.authority.certificate.algorithm == "ec" %}ECDHE-ECDSA{% else %}DHE-RSA{% endif %}-WITH-AES-128-GCM-SHA384
cipher AES-128-GCM
auth SHA384
mute-replay-warnings
reneg-sec 0
remote-cert-tls server
dev tun
persist-tun
persist-key
ca /etc/certidude/authority/{{ authority_name }}/ca_cert.pem
key /etc/certidude/authority/{{ authority_name }}/host_key.pem
cert /etc/certidude/authority/{{ authority_name }}/host_cert.pem
EOF

systemctl restart openvpn
