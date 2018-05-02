# Install packages on Ubuntu & Fedora, patch Fedora paths
which apt && apt install strongswan
which dnf && dnf install strongswan
test -e /etc/strongswan && test -e /etc/ipsec.conf || ln -s strongswan/ipsec.conf /etc/ipsec.conf
test -e /etc/strongswan && test -e /etc/ipsec.d || ln -s strongswan/ipsec.d /etc/ipsec.d
test -e /etc/strongswan && test -e /etc/ipsec.secrets || ln -s strongswan/ipsec.secrets /etc/ipsec.secrets

# Set SELinux context
chcon --type=home_cert_t /etc/certidude/authority/{{ authority_name }}/ca_cert.pem /etc/ipsec.d/cacerts/{{ authority_name }}.pem
chcon --type=home_cert_t  /etc/certidude/authority/{{ authority_name }}/host_cert.pem /etc/ipsec.d/certs/{{ authority_name }}.pem
chcon --type=home_cert_t  /etc/certidude/authority/{{ authority_name }}/host_key.pem /etc/ipsec.d/private/{{ authority_name }}.pem

# Patch AppArmor
cat << EOF > /etc/apparmor.d/local/usr.lib.ipsec.charon
/etc/certidude/authority/**
EOF
