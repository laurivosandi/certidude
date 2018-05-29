opkg update
opkg install curl openssl-util openvpn-openssl

{% if session.authority.certificate.algorithm != "ec" %}
# Generate Diffie-Hellman parameters file for OpenVPN
test -e /etc/certidude/dh.pem \
|| openssl dhparam 2048 -out /etc/certidude/dh.pem
{% endif %}
# Create interface definition for tunnel
uci set network.vpn=interface
uci set network.vpn.name='vpn'
uci set network.vpn.ifname=tun_s2c_udp tun_s2c_tcp
uci set network.vpn.proto='none'

# Create zone definition for VPN interface
uci set firewall.vpn=zone
uci set firewall.vpn.name='vpn'
uci set firewall.vpn.input='ACCEPT'
uci set firewall.vpn.forward='ACCEPT'
uci set firewall.vpn.output='ACCEPT'
uci set firewall.vpn.network='vpn'

# Allow UDP 1194 on WAN interface
uci set firewall.openvpn=rule
uci set firewall.openvpn.name='Allow OpenVPN'
uci set firewall.openvpn.src='wan'
uci set firewall.openvpn.dest_port=1194
uci set firewall.openvpn.proto='udp'
uci set firewall.openvpn.target='ACCEPT'

# Allow TCP 443 on WAN interface
uci set firewall.openvpn=rule
uci set firewall.openvpn.name='Allow OpenVPN over TCP'
uci set firewall.openvpn.src='wan'
uci set firewall.openvpn.dest_port=443
uci set firewall.openvpn.proto='tcp'
uci set firewall.openvpn.target='ACCEPT'

# Forward traffic from VPN to LAN
uci set firewall.c2s=forwarding
uci set firewall.c2s.src='vpn'
uci set firewall.c2s.dest='lan'

# Permit DNS queries from VPN
uci set dhcp.@dnsmasq[0].localservice='0'

touch /etc/config/openvpn

# Configure OpenVPN over TCP
uci set openvpn.s2c_tcp=openvpn
uci set openvpn.s2c_tcp.local=$(uci get network.wan.ipaddr)
uci set openvpn.s2c_tcp.server='10.179.43.0 255.255.255.128'
uci set openvpn.s2c_tcp.proto='tcp-server'
uci set openvpn.s2c_tcp.port='443'
uci set openvpn.s2c_tcp.dev=tun_s2c_tcp

# Configure OpenVPN over UDP
uci set openvpn.s2c_udp=openvpn
uci set openvpn.s2c_udp.local=$(uci get network.wan.ipaddr)
uci set openvpn.s2c_udp.server='10.179.43.128 255.255.255.128'
uci set openvpn.s2c_tcp.dev=tun_s2c_udp

for section in s2c_tcp s2c_udp; do

# Common paths
uci set openvpn.$section.script_security=2
uci set openvpn.$section.client_connect='/etc/certidude/updown'
uci set openvpn.$section.key='/etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem'
uci set openvpn.$section.cert='/etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem'
uci set openvpn.$section.ca='/etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem'
{% if session.authority.certificate.algorithm != "ec" %}uci set openvpn.$section.dh='/etc/certidude/dh.pem'{% endif %}
uci set openvpn.$section.enabled=1

# DNS and routes
uci add_list openvpn.$section.push="route-metric 1000"
uci add_list openvpn.$section.push="route $(uci get network.lan.ipaddr) $(uci get network.lan.netmask)"
uci add_list openvpn.$section.push="dhcp-option DNS $(uci get network.lan.ipaddr)"
uci add_list openvpn.$section.push="dhcp-option DOMAIN $(uci get dhcp.@dnsmasq[0].domain)"

# Security hardening
uci set openvpn.$section.tls_version_min='1.2'
uci set openvpn.$section.tls_cipher='TLS-{% if session.authority.certificate.algorithm == "ec" %}ECDHE-ECDSA{% else %}DHE-RSA{% endif %}-WITH-AES-128-GCM-SHA384'
uci set openvpn.$section.cipher='AES-128-GCM'
uci set openvpn.$section.auth='SHA384'

done

/etc/init.d/openvpn restart
/etc/init.d/firewall restart
