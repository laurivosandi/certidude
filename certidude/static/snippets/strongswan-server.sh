# Generate StrongSwan config
cat > /etc/ipsec.conf << EOF
config setup
    strictcrlpolicy=yes
    uniqueids=yes

ca {{ authority_name }}
    auto=add
    cacert=/etc/certidude/authority/{{ authority_name }}/ca_cert.pem
{% if session.features.crl %}    crluri=http://{{ authority_name }}/api/revoked/{% endif %}
{% if session.features.ocsp %}    ocspuri=http://{{ authority_name }}/api/ocsp/{% endif %}

conn default-{{ authority_name }}
    ike=aes256-sha384-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    esp=aes128gcm16-aes128gmac-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    left=$(uci get network.wan.ipaddr) # Bind to this IP address
    leftid={{ session.service.routers | first }}
    leftupdown=/etc/certidude/authority/{{ authority_name }}/updown
    leftcert=/etc/certidude/authority/{{ authority_name }}/host_cert.pem
    leftsubnet=$(uci get network.lan.ipaddr | cut -d . -f 1-3).0/24 # Subnets pushed to roadwarriors
    leftdns=$(uci get network.lan.ipaddr) # IP of DNS server advertised to roadwarriors
    leftca="{{ session.authority.certificate.distinguished_name }}"
    rightca="{{ session.authority.certificate.distinguished_name }}"
    rightsourceip=172.21.0.0/24 # Roadwarrior virtual IP pool
    dpddelay=0
    dpdaction=clear

conn site-to-clients
    auto=add
    also=default-{{ authority_name }}

conn site-to-client1
    auto=ignore
    also=default-{{ authority_name }}
    rightid="CN=*, OU=IP Camera, O=*, DC=*, DC=*, DC=*"
    rightsourceip=172.21.0.1

EOF

echo ": {% if session.authority.certificate.algorithm == "ec" %}ECDSA{% else %}RSA{% endif %} /etc/certidude/authority/{{ authority_name }}/host_key.pem" > /etc/ipsec.secrets

