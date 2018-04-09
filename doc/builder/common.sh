#!/bin/bash

set -e
set -x
umask 022

VERSION=17.01.4
BASENAME=lede-imagebuilder-$VERSION-ar71xx-generic.Linux-x86_64
FILENAME=$BASENAME.tar.xz
URL=http://downloads.lede-project.org/releases/$VERSION/targets/ar71xx/generic/$FILENAME

if [ ! -e $BUILD/$FILENAME ]; then
    wget -q $URL -O $BUILD/$FILENAME
fi

if [ ! -e $BUILD/$BASENAME ]; then
    tar xf $BUILD/$FILENAME -C $BUILD
fi

# Copy CA certificate
AUTHORITY=$(hostname -f)
CERTIDUDE_DIR=/var/lib/certidude/$AUTHORITY

mkdir -p $OVERLAY/etc/config
mkdir -p $OVERLAY/etc/uci-defaults
mkdir -p $OVERLAY/etc/certidude/authority/$AUTHORITY
cp /var/lib/certidude/$AUTHORITY/ca_cert.pem $OVERLAY/etc/certidude/authority/$AUTHORITY/

cat <<EOF > $OVERLAY/etc/config/certidude

config authority
    option gateway router.k-space.ee
    option url http://$AUTHORITY
    option trigger wan
    option authority_path /etc/certidude/authority/$AUTHORITY/ca_cert.pem
    option request_path /etc/certidude/authority/$AUTHORITY/client_req.pem
    option certificate_path /etc/certidude/authority/$AUTHORITY/client_cert.pem
    option key_path /etc/certidude/authority/$AUTHORITY/client_key.pem
    option key_type rsa
    option key_length 2048

EOF

cat << EOF > $OVERLAY/etc/uci-defaults/40-disable-ipsec
/etc/init.d/ipsec disable
EOF



cat << EOF > $OVERLAY/etc/ipsec.secrets
: RSA /etc/certidude/authority/$AUTHORITY/client_key.pem
EOF

cat << EOF > $OVERLAY/etc/ipsec.conf

config setup

ca $AUTHORITY
	cacert=/etc/certidude/authority/$AUTHORITY/ca_cert.pem
	auto=add

conn router.k-space.ee
	right=router.k-space.ee
	dpdaction=restart
	auto=start
	rightsubnet=0.0.0.0/0
	rightid=%any
	leftsourceip=%config
	keyexchange=ikev2
	closeaction=restart
	leftcert=/etc/certidude/authority/$AUTHORITY/client_cert.pem
	left=%defaultroute

EOF


