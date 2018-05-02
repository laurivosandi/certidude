#!/bin/bash

source common.sh

sed -e 's/trigger wan/trigger lan/' -i $OVERLAY/etc/config/certidude

cat << \EOF > $OVERLAY/etc/uci-defaults/40-hostname

MODEL=$(cat /etc/board.json | jsonfilter -e '@["model"]["id"]')

# Hostname prefix
case $MODEL in
    tl-*|archer-*)  VENDOR=tplink ;;
    cf-*) VENDOR=comfast ;;
    *) VENDOR=ap ;;
esac

# Network interface with relevant MAC address
case $MODEL in
    tl-wdr*) NIC=wlan1 ;;
    archer-*)  NIC=eth1 ;;
    cf-e380ac-v2) NIC=eth0 ;;
    *) NIC=wlan0 ;;
esac

HOSTNAME=$VENDOR-$(cat /sys/class/net/$NIC/address | cut -d : -f 4- | sed -e 's/://g')
uci set system.@system[0].hostname=$HOSTNAME
uci set network.lan.hostname=$HOSTNAME

EOF

cat << \EOF > $OVERLAY/etc/uci-defaults/50-access-point

# Remove firewall rules since AP bridges ethernet to wireless anyway
uci delete firewall.@zone[1]
uci delete firewall.@zone[0]
uci delete firewall.@forwarding[0]
for j in $(seq 0 10); do uci delete firewall.@rule[0]; done

# Remove WAN interface
uci delete network.wan
uci delete network.wan6

# Reconfigure DHCP client for bridge over LAN and WAN ports
uci delete network.lan.ipaddr
uci delete network.lan.netmask
uci delete network.lan.ip6assign
uci delete network.globals.ula_prefix
uci delete network.@switch_vlan[1]
uci delete dhcp.@dnsmasq[0].domain
uci set network.lan.proto=dhcp
uci set network.lan.ipv6=0
uci set network.lan.ifname='eth0'
uci set network.lan.stp=1

# Radio ordering differs among models
case $(uci get wireless.radio0.hwmode) in
    11a) uci rename wireless.radio0=radio5ghz;;
    11g) uci rename wireless.radio0=radio2ghz;;
esac
case $(uci get wireless.radio1.hwmode) in
    11a) uci rename wireless.radio1=radio5ghz;;
    11g) uci rename wireless.radio1=radio2ghz;;
esac

# Reset virtual SSID-s
uci delete wireless.@wifi-iface[1]
uci delete wireless.@wifi-iface[0]

# Pseudorandomize channel selection, should work with 80MHz on 5GHz band
case $(uci get system.@system[0].hostname | md5sum) in
   1*|2*|3*|4*) uci set wireless.radio2ghz.channel=1; uci set wireless.radio5ghz.channel=36 ;;
   5*|6*|7*|8*) uci set wireless.radio2ghz.channel=5; uci set wireless.radio5ghz.channel=52 ;;
   9*|0*|a*|b*) uci set wireless.radio2ghz.channel=9; uci set wireless.radio5ghz.channel=100 ;;
   c*|d*|e*|f*) uci set wireless.radio2ghz.channel=13; uci set wireless.radio5ghz.channel=132 ;;
esac

# Create bridge for guests
uci set network.guest=interface
uci set network.guest.proto='static'
uci set network.guest.address='0.0.0.0'
uci set network.guest.type='bridge'
uci set network.guest.ifname='eth0.156' # tag id 156 for guest network
uci set network.guest.ipaddr='0.0.0.0'
uci set network.guest.ipv6=0
uci set network.guest.stp=1

# Add VPN interface for IPSec
uci set network.vpn=interface
uci set network.vpn.ifname='ipsec0'
uci set network.vpn.proto='none'

uci set firewall.vpn=zone
uci set firewall.vpn.name="vpn"
uci set firewall.vpn.input="ACCEPT"
uci set firewall.vpn.forward="ACCEPT"
uci set firewall.vpn.output="ACCEPT"
uci set firewall.vpn.network="vpn"

# Disable switch tagging and bridge all ports on TP-Link WDR3600/WDR4300
case $(cat /etc/board.json | jsonfilter -e '@["model"]["id"]') in
    tl-wdr*|archer*)
        uci set network.@switch[0].enable_vlan=0
        uci set network.@switch_vlan[0].ports='0 1 2 3 4 5 6'
    ;;
    *) ;;
esac

EOF

make -C $BUILD/$BASENAME image FILES=$OVERLAY PROFILE=$PROFILE PACKAGES="luci \
    openssl-util curl ca-certificates dropbear \
    strongswan-mod-kernel-libipsec kmod-tun strongswan-default strongswan-mod-openssl strongswan-mod-curl strongswan-mod-ccm strongswan-mod-gcm \
    htop iftop tcpdump nmap nano -odhcp6c -odhcpd -dnsmasq \
    -luci-app-firewall \
    -pppd -luci-proto-ppp -kmod-ppp -ppp -ppp-mod-pppoe \
    -kmod-ip6tables -ip6tables -luci-proto-ipv6 -kmod-iptunnel6 -kmod-ipsec6"

