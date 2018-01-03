#!/bin/bash

set -e
set -x
umask 022

VERSION=17.01.4
BASENAME=lede-imagebuilder-$VERSION-ar71xx-generic.Linux-x86_64
FILENAME=$BASENAME.tar.xz
URL=http://downloads.lede-project.org/releases/$VERSION/targets/ar71xx/generic/$FILENAME

PACKAGES="luci luci-app-commands \
    collectd collectd-mod-conntrack collectd-mod-interface \
    collectd-mod-iwinfo collectd-mod-load collectd-mod-memory \
    collectd-mod-network collectd-mod-protocols collectd-mod-tcpconns \
    collectd-mod-uptime \
    openssl-util openvpn-openssl curl ca-certificates \
    htop iftop tcpdump nmap nano -odhcp6c -odhcpd -dnsmasq \
    -luci-app-firewall \
    -pppd -luci-proto-ppp -kmod-ppp -ppp -ppp-mod-pppoe \
    -kmod-ip6tables -ip6tables -luci-proto-ipv6 -kmod-iptunnel6 -kmod-ipsec6"


if [ ! -e $FILENAME ]; then
    wget -q $URL
fi

if [ ! -e $BASENAME ]; then
    tar xf $FILENAME
fi

cd $BASENAME

# Copy CA certificate
AUTHORITY=$(hostname -f)
CERTIDUDE_DIR=/var/lib/certidude/$AUTHORITY
if [ -d "$CERTIDUDE_DIR" ]; then
    mkdir -p overlay/$CERTIDUDE_DIR
    cp $CERTIDUDE_DIR/ca_cert.pem overlay/$CERTIDUDE_DIR
fi

cat < EOF > overlay/etc/config/certidude

config authority
    option url http://$AUTHORITY
    option authority_path /var/lib/certidude/$AUTHORITY/ca_cert.pem
    option request_path /var/lib/certidude/$AUTHORITY/client_req.pem
    option certificate_path /var/lib/certidude/$AUTHORITY/client_cert.pem
    option key_path /var/lib/certidude/$AUTHORITY/client_key.pem
    option key_type rsa
    option key_length 1024
    option red_led gl-connect:red:wlan
    option green_led gl-connect:green:lan

EOF

make image FILES=../overlay/ PACKAGES="$PACKAGES" PROFILE="$PROFILE"

