# Install packages on Ubuntu & Fedora
which apt && apt install openvpn
which dnf && dnf install openvpn

# Create OpenVPN configuration file
cat > /etc/openvpn/{{ session.authority.hostname }}.conf << EOF
{% include "snippets/openvpn-client.conf" %}
EOF

# Restart OpenVPN service
systemctl restart openvpn
{#

Some notes:

- Ubuntu 16.04 ships OpenVPN 2.3 which doesn't support AES-128-GCM
- NetworkManager's OpenVPN profile importer doesn't understand multiple remotes
- Tunnelblick and OpenVPN Connect apps don't have a method to update CRL

#}
