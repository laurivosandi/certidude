# OpenWrt/LEDE integration guide

## Software dependencies

On vanilla OpenWrt/LEDE box install software packages:

```bash
opkg update
opkg install curl openssl-util
opkg install strongswan-full kmod-crypto-echainiv kmod-crypto-gcm
```

When using image builder specify these packages via PACKAGES environment variable.

Grab 50-certidude script and place it to /etc/hotplug.d/iface/50-certidude:

```bash
wget https://raw.githubusercontent.com/laurivosandi/certidude/master/doc/50-certidude -O /etc/hotplug.d/iface/50-certidude
```

## As IPSec gateway

Configure /etc/ipsec.conf:

```
config setup
    cachecrls=yes
    strictcrlpolicy=yes

ca ca2
    auto = add
    cacert = /etc/config/ca.crt
    ocspuri = http://ca.example.com/api/ocsp/

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    keyexchange=ikev2

conn site-to-client
    auto=add
    right=%any # Allow connecting from any IP address
    rightsourceip=10.179.44.0/24 # Serve virtual IP-s from this pool
    left=router.example.com # Gateway FQDN
    leftcert=/etc/config/robo-router.crt # Gateway certificate
    leftupdown=/usr/bin/certidude-updown
    leftsubnet=192.168.12.0/24,10.179.0.0/16 # Push routes
    rightdns=192.168.12.1 # Push DNS server to clients
```

When you want to make DNS queries possible via tunnel don't forget to 
disable local service for dnsmasq:

```bash
uci set dhcp.@dnsmasq[0].localservice=0
uci commit
```

Place following to /usr/bin/certidude-updown, when tunnel goes up submit lease to CA:

```bash
#!/bin/sh

case $PLUTO_VERB in
  up-client)
    curl -f --data "outer_address=$PLUTO_PEER&inner_address=$PLUTO_PEER_SOURCEIP&client=$(echo $PLUTO_PEER_ID | cut -d '=' -f 2)" \
      http://ca.example.com/api/lease/
  ;;
  *)
    curl -f -X POST -d "client=$X509_0_CN&server=$X509_1_CN&outer_address=$untrusted_ip&inner_address=$ifconfig_pool_remote_ip&serial=$tls_serial_0" \
      http://ca.example.com/api/lease/
  ;;
esac
```


## As client

Grab 50-certidude script and place it to /etc/hotplug.d/iface/ as shown above.

Place following to /etc/ipsec.conf:

```
config setup

conn %default
        keyexchange=ikev2
        keyingtries=300
        dpdaction=restart
        closeaction=restart

conn client-to-site
        auto=add
        leftupdown=/usr/bin/ipsec-updown
        left=%defaultroute
        leftsourceip=%config
        leftcert=/etc/ipsec.d/certs/client.pem
        right=router.example.com
        rightsubnet=0.0.0.0/0
```

Scripting client, when tunnel goes up:

```bash
#!/bin/sh
[ "$PLUTO_VERB" != "up-client" ] && exit 0

case "$PLUTO_PEER_CLIENT" in
    192.*|172.*|10.*)
        # Do nothing
        exit 0
    ;;
    *)
        # Attempt to fetch script from server
        logger -t certidude -s "IPsec SA to $PLUTO_PEER_CLIENT established, attempting to fetch script"
        SCRIPT=$(mktemp -u)
        wget --header='Accept: text/x-shellscript' http://ca.example.com/api/script -O $SCRIPT
        sh $SCRIPT
    ;;
esac
```
at /etc/config/certidude you can use:

```
config authority
    option url http://ca.example.com
    option authority_path /etc/ipsec.d/cacerts/ca.pem
    option request_path /etc/ipsec.d/reqs/client.pem
    option certificate_path /etc/ipsec.d/certs/client.pem
    option key_path /etc/ipsec.d/private/client.pem
    option key_type rsa
    option key_length 1024
    option red_led gl-connect:red:wlan
    option green_led gl-connect:green:lan
```

To test:

```bash
ACTION=ifup INTERFACE=wan sh /etc/hotplug.d/iface/50-certidude
```

# As site-to-site router

In this example Omnia Turris is set up as a router which enables
access to a subnet behind another IPSec gateway.

Set up /etc/config/certidude:

```bash
config authority ca
    option key_type rsa
    option key_length 1024
    option url http://ca.example.com
    option common_name turris-123456 
    option key_path /etc/ipsec.d/private/router.pem
    option request_path /etc/ipsec.d/reqs/router.pem
    option certificate_path /etc/ipsec.d/certs/router.pem
    option authority_path /etc/ipsec.d/cacerts/ca.pem
    option revocations_path /etc/ipsec.d/crls/router.pem
    option red_led omnia-led:user1
    option green_led omnia-led:user2
```

Set up /etc/ipsec.conf:

```
config setup
    cachecrls=yes
    strictcrlpolicy=yes

conn s2s
    auto=start
    right=router.example.com
    leftcert=/etc/ipsec.d/certs/router.pem
    leftsubnet=172.26.1.0/24 # local subnet
    rightsubnet=172.24.0.0/24 # subnet behind gateway
```

Reconfigure firewall:

```bash
# Prevent NAT-ing of IPSec tunnel packets
iptables -t nat -I POSTROUTING -m policy --dir out --pol ipsec -j ACCEPT

# Trust packets from IPSec tunnel
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
iptables -I FORWARD -m policy --dir in --pol ipsec -j ACCEPT
```

DNS forwarding and caching:

```bash
uci delete dhcp.@dnsmasq[0].local
uci set dhcp.@dnsmasq[0].domain=example.lan
uci add_list dhcp.@dnsmasq[0].server="/.example.lan/172.24.1.1"
uci add_list dhcp.@dnsmasq[0].rebind_domain="example.lan"
uci commit
```

On Omnia turris kresd is used instead of dnsmasq, to revert back to dnsmasq:

```bash
/etc/init.d/kresd stop
/etc/init.d/kresd disable
uci del_list dhcp.lan.dhcp_option="6,192.168.1.1"
uci delete dhcp.@dnsmasq[0].port
uci commit
/etc/init.d/dnsmasq enable
/etc/init.d/dnsmasq restart
```

To disable IPv6:

```bash
/etc/init.d/odhcpd stop
/etc/init.d/odhcpd disable
```

