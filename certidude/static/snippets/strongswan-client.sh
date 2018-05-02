cat > /etc/ipsec.conf << EOF

ca {{ authority_name }}
    auto=add
    cacert=/etc/certidude/authority/{{ authority_name }}/ca_cert.pem
{% if session.features.crl %}    crluri=http://{{ authority_name }}/api/revoked/{% endif %}
{% if session.features.ocsp %}    ocspuri=http://{{ authority_name }}/api/ocsp/{% endif %}

conn client-to-site
    auto=start
    right={{ session.service.routers[0] }}
    rightsubnet=0.0.0.0/0
    rightca="{{ session.authority.certificate.distinguished_name }}"
    left=%defaultroute
    leftcert=/etc/certidude/authority/{{ authority_name }}/host_cert.pem
    leftsourceip=%config
    leftca="{{ session.authority.certificate.distinguished_name }}"
    keyexchange=ikev2
    keyingtries=%forever
    dpdaction=restart
    closeaction=restart
    ike=aes256-sha384-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!
    esp=aes128gcm16-aes128gmac-{% if session.authority.certificate.algorithm == "ec" %}ecp384{% else %}modp2048{% endif %}!

EOF

echo ": {% if session.authority.certificate.algorithm == "ec" %}ECDSA{% else %}RSA{% endif %} {{ authority_name }}.pem" > /etc/ipsec.secrets

ipsec restart
