#!/bin/bash

. common.sh

cat << \EOF > $OVERLAY/etc/uci-defaults/40-hostname

HOSTNAME=mfp-$(cat /sys/class/net/eth0/address | cut -d : -f 4- | sed -e 's/://g')
uci set system.@system[0].hostname=$HOSTNAME
uci set network.wan.hostname=$HOSTNAME

EOF

mkdir -p $OVERLAY/etc/config/
touch $OVERLAY/etc/config/wireless

cat << EOF > $OVERLAY/etc/uci-defaults/50-mfp

# Disable rebind protection for DNS
uci set dhcp.@dnsmasq[0].rebind_protection=0
uci set dhcp.@dnsmasq[0].domain='mfp.lan'
uci delete dhcp.@dnsmasq[0].local

# Disable bridge for LAN since WiFi is disabled
uci delete network.lan.type
uci set dhcp.lan.limit=1

uci set network.vpn=interface
uci set network.vpn.ifname='ipsec0'
uci set network.vpn.proto='none'

uci set firewall.vpn=zone
uci set firewall.vpn.name="vpn"
uci set firewall.vpn.input="ACCEPT"
uci set firewall.vpn.forward="ACCEPT"
uci set firewall.vpn.output="ACCEPT"
uci set firewall.vpn.network="vpn"
uci set firewall.vpn.masq='1'

uci set firewall.lan2vpn=forwarding
uci set firewall.lan2vpn.src='lan'
uci set firewall.lan2vpn.dest='vpn'

uci set firewall.allow_ipp=redirect
uci set firewall.allow_ipp.name="Allow-IPP-on-MFP"
uci set firewall.allow_ipp.src=vpn
uci set firewall.allow_ipp.src_dport=631
uci set firewall.allow_ipp.dest=lan
uci set firewall.allow_ipp.dest_ip=192.168.1.100
uci set firewall.allow_ipp.target=DNAT
uci set firewall.allow_ipp.proto=tcp

uci set firewall.allow_http=redirect
uci set firewall.allow_http.name="Allow-HTTP-on-MFP"
uci set firewall.allow_http.src=vpn
uci set firewall.allow_http.src_dport=80
uci set firewall.allow_http.dest=lan
uci set firewall.allow_http.dest_ip=192.168.1.100
uci set firewall.allow_http.target=DNAT
uci set firewall.allow_http.proto=tcp

uci set firewall.allow_https=redirect
uci set firewall.allow_https.name="Allow-HTTPS-on-MFP"
uci set firewall.allow_https.src=vpn
uci set firewall.allow_https.src_dport=443
uci set firewall.allow_https.dest=lan
uci set firewall.allow_https.dest_ip=192.168.1.100
uci set firewall.allow_https.target=DNAT
uci set firewall.allow_https.proto=tcp

uci set firewall.allow_jetdirect=redirect
uci set firewall.allow_jetdirect.name="Allow-JetDirect-on-MFP"
uci set firewall.allow_jetdirect.src=vpn
uci set firewall.allow_jetdirect.src_dport=9100
uci set firewall.allow_jetdirect.dest=lan
uci set firewall.allow_jetdirect.dest_ip=192.168.1.100
uci set firewall.allow_jetdirect.target=DNAT
uci set firewall.allow_jetdirect.proto=tcp
uci set firewall.allow_jetdirect.enabled=0

uci set firewall.allow_snmp=redirect
uci set firewall.allow_snmp.name="Allow-SNMP-on-MFP"
uci set firewall.allow_snmp.src=vpn
uci set firewall.allow_snmp.src_dport=161
uci set firewall.allow_snmp.dest=lan
uci set firewall.allow_snmp.dest_ip=192.168.1.100
uci set firewall.allow_snmp.target=DNAT
uci set firewall.allow_snmp.proto=udp
uci set firewall.allow_snmp.enabled=0

uci set firewall.allow_lpd=redirect
uci set firewall.allow_lpd.name="Allow-LPD-on-MFP"
uci set firewall.allow_lpd.src=vpn
uci set firewall.allow_lpd.src_dport=515
uci set firewall.allow_lpd.dest=lan
uci set firewall.allow_lpd.dest_ip=192.168.1.100
uci set firewall.allow_lpd.target=DNAT
uci set firewall.allow_lpd.proto=tcp
uci set firewall.allow_lpd.enabled=0

/etc/init.d/dropbear disable

uci set uhttpd.main.listen_http=0.0.0.0:8080

EOF

make -C $BUILD/$BASENAME image FILES=$OVERLAY PROFILE=$PROFILE PACKAGES="openssl-util curl ca-certificates htop \
    iftop tcpdump nmap nano mtr patch diffutils ipset usbutils luci dropbear kmod-tun netdata \
    strongswan-default strongswan-mod-kernel-libipsec strongswan-mod-openssl strongswan-mod-curl strongswan-mod-ccm strongswan-mod-gcm \
    -odhcpd -odhcp6c -kmod-ath9k picocom libustream-openssl kmod-crypto-gcm \
    -pppd -luci-proto-ppp -kmod-ppp -ppp -ppp-mod-pppoe \
    -kmod-ip6tables -ip6tables -luci-proto-ipv6 -kmod-iptunnel6 -kmod-ipsec6"

