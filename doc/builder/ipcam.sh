#!/bin/bash

. common.sh

cat << \EOF > $OVERLAY/etc/uci-defaults/40-hostname

HOSTNAME=cam-$(cat /sys/class/net/eth0/address | cut -d : -f 4- | sed -e 's/://g')
uci set system.@system[0].hostname=$HOSTNAME
uci set network.wan.hostname=$HOSTNAME

EOF

touch $OVERLAY/etc/config/wireless

cat << EOF > $OVERLAY/etc/uci-defaults/50-ipcam

uci delete network.lan
uci delete network.wan6

uci set network.vpn=interface
uci set network.vpn.ifname='ipsec0'
uci set network.vpn.proto='none'
uci set firewall.@zone[0].network=vpn
uci delete firewall.@forwarding[0]

uci set mjpg-streamer.core.enabled=1
uci set mjpg-streamer.core.quality=''
uci set mjpg-streamer.core.resolution='1280x720'
uci delete mjpg-streamer.core.username
uci delete mjpg-streamer.core.password

uci certidude.@authority[0].red_led='gl-connect:red:wlan'
uci certidude.@authority[0].green_led='gl-connect:green:lan'

/etc/init.d/dropbear disable
/etc/init.d/ipsec disable

EOF


make -C $BUILD/$BASENAME image FILES=$OVERLAY PROFILE=$PROFILE PACKAGES="openssl-util curl ca-certificates \
    strongswan-default strongswan-mod-openssl strongswan-mod-curl strongswan-mod-ccm strongswan-mod-gcm htop \
    iftop tcpdump nmap nano mtr patch diffutils ipset usbutils luci luci-app-mjpg-streamer kmod-video-uvc dropbear \
    pciutils -dnsmasq -odhcpd -odhcp6c -kmod-ath9k picocom strongswan-mod-kernel-libipsec kmod-tun bc"
