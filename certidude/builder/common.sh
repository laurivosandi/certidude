#!/bin/bash

set -e
set -x
umask 022

VERSION=18.06.1
BASENAME=openwrt-imagebuilder-$VERSION-ar71xx-generic.Linux-x86_64
FILENAME=$BASENAME.tar.xz
URL=http://downloads.openwrt.org/releases/$VERSION/targets/ar71xx/generic/$FILENAME

# curl of vanilla OpenWrt a the moment
# - doesn't support ECDSA
# - is compiled against embedded TLS library which doesn't support OCSP
BASENAME=openwrt-imagebuilder-ar71xx-generic.Linux-x86_64
FILENAME=$BASENAME.tar.xz
URL=https://www.koodur.com/$FILENAME

if [ ! -e $BUILD/$FILENAME ]; then
    wget -q $URL -O $BUILD/$FILENAME
fi

if [ ! -e $BUILD/$BASENAME ]; then
    tar xf $BUILD/$FILENAME -C $BUILD
fi

# Copy CA certificate
AUTHORITY=$(hostname -f)

mkdir -p $OVERLAY/etc/config
mkdir -p $OVERLAY/etc/uci-defaults
mkdir -p $OVERLAY/etc/certidude/authority/$AUTHORITY/
cp /var/lib/certidude/ca_cert.pem $OVERLAY/etc/certidude/authority/$AUTHORITY/

cat <<EOF > $OVERLAY/etc/config/certidude

config authority
    option gateway "$ROUTER"
    option hostname "$AUTHORITY"
    option trigger wan
    option key_type $AUTHORITY_CERTIFICATE_ALGORITHM
    option key_length 2048
    option key_curve secp384r1

EOF

case $AUTHORITY_CERTIFICATE_ALGORITHM in
    rsa)
        echo ": RSA /etc/certidude/authority/$AUTHORITY/host_key.pem" >> $OVERLAY/etc/ipsec.secrets
        ;;
    ec)
        echo ": ECDSA /etc/certidude/authority/$AUTHORITY/host_key.pem" >> $OVERLAY/etc/ipsec.secrets
        ;;
    *)
        echo "Unknown algorithm $AUTHORITY_CERTIFICATE_ALGORITHM"
        exit 1
        ;;
esac

cat << EOF > $OVERLAY/etc/certidude/authority/$AUTHORITY/updown
#!/bin/sh

CURL="curl -m 3 -f --key /etc/certidude/authority/$AUTHORITY/host_key.pem --cert /etc/certidude/authority/$AUTHORITY/host_cert.pem --cacert /etc/certidude/authority/$AUTHORITY/ca_cert.pem --cert-status"
URL="https://$AUTHORITY:8443/api/signed/\$(uci get system.@system[0].hostname)/script/"

case \$PLUTO_VERB in
  up-client)
    logger -t certidude -s "Downloading and executing \$URL"
    \$CURL \$URL -o /tmp/script.sh && sh /tmp/script.sh
  ;;
  *) ;;
esac
EOF

chmod +x  $OVERLAY/etc/certidude/authority/$AUTHORITY/updown

cat << EOF > $OVERLAY/etc/ipsec.conf

config setup
    strictcrlpolicy=yes

ca $AUTHORITY
    auto=add
    cacert=/etc/certidude/authority/$AUTHORITY/ca_cert.pem
    # OCSP and CRL URL-s embedded in certificates

conn %default
    keyingtries=%forever
    dpdaction=restart
    closeaction=restart
    ike=$IKE
    esp=$ESP
    left=%defaultroute
    leftcert=/etc/certidude/authority/$AUTHORITY/host_cert.pem
    leftca="$AUTHORITY_CERTIFICATE_DISTINGUISHED_NAME"
    rightca="$AUTHORITY_CERTIFICATE_DISTINGUISHED_NAME"

conn c2s
    auto=start
    right="$ROUTER"
    rightsubnet="$SUBNETS"
    leftsourceip=%config
    leftupdown=/etc/certidude/authority/$AUTHORITY/updown

EOF

# Note that auto=route is not supported at the moment with libipsec
