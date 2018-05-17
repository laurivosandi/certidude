#!/bin/bash

set -e
set -x
umask 022

VERSION=17.01.4
BASENAME=lede-imagebuilder-$VERSION-ar71xx-generic.Linux-x86_64
FILENAME=$BASENAME.tar.xz
URL=http://downloads.lede-project.org/releases/$VERSION/targets/ar71xx/generic/$FILENAME

# curl of vanilla LEDE doesn't support ECDSA at the moment
BASENAME=lede-imagebuilder-ar71xx-generic.Linux-x86_64
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

CURL="curl -m 3 -f --key /etc/certidude/authority/$AUTHORITY/host_key.pem --cert /etc/certidude/authority/$AUTHORITY/host_cert.pem --cacert /etc/certidude/authority/$AUTHORITY/ca_cert.pem"
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
    ocspuri = http://$AUTHORITY/api/ocsp/

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

conn client-to-site
    auto=start
    right="$ROUTER"
    rightsubnet="$SUBNETS"
    leftsourceip=%config
    leftupdown=/etc/certidude/authority/$AUTHORITY/updown

EOF

cat << EOF > $OVERLAY/etc/uci-defaults/99-uhttpd-disable-https
uci delete uhttpd.main.listen_https
uci delete uhttpd.main.redirect_https
EOF
