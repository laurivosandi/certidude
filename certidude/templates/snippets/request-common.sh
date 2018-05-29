# Delete CA certificate if checksum doesn't match
echo {{ session.authority.certificate.md5sum }} /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem | md5sum -c \
 || rm -fv /etc/certidude/authority/{{ session.authority.hostname }}/*.pem
{% include "snippets/store-authority.sh" %}
{% include "snippets/update-trust.sh" %}
# Generate private key
test -e /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem \
 || {% if session.authority.certificate.algorithm == "ec" %}openssl ecparam -name secp384r1 -genkey -noout \
 -out /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem{% else %}openssl genrsa \
 -out /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem 2048{% endif %}
test -e /etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem \
 || openssl req -new -sha384 -subj "/CN=$NAME" \
 -key /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem \
 -out /etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem
echo "If CSR submission fails, you can copy paste it to Certidude:"
cat /etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem
