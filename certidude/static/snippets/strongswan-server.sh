# Generate StrongSwan config
cat > /etc/ipsec.conf << EOF
config setup
    strictcrlpolicy=yes
    uniqueids=yes

ca {{ session.authority.hostname }}
    auto=add
    cacert=/etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem

conn default-{{ session.authority.hostname }}
    ike=aes256-sha384-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    esp=aes128gcm16-aes128gmac-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    left=$(uci get network.wan.ipaddr) # Bind to this IP address
    leftid={{ session.service.routers | first }}
    leftupdown=/etc/certidude/authority/{{ session.authority.hostname }}/updown
    leftcert=/etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem
    leftsubnet=$(uci get network.lan.ipaddr | cut -d . -f 1-3).0/24 # Subnets pushed to roadwarriors
    leftdns=$(uci get network.lan.ipaddr) # IP of DNS server advertised to roadwarriors
    leftca="{{ session.authority.certificate.distinguished_name }}"
    rightca="{{ session.authority.certificate.distinguished_name }}"
    rightsourceip=172.21.0.0/24 # Roadwarrior virtual IP pool
    dpddelay=0
    dpdaction=clear

conn site-to-clients
    auto=add
    also=default-{{ session.authority.hostname }}

conn site-to-client1
    auto=ignore
    also=default-{{ session.authority.hostname }}
    rightid="CN=*, OU=IP Camera, O=*, DC=*, DC=*, DC=*"
    rightsourceip=172.21.0.1

EOF

echo ": {% if session.authority.certificate.algorithm == "ec" %}ECDSA{% else %}RSA{% endif %} /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem" > /etc/ipsec.secrets

