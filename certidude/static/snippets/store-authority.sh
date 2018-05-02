mkdir -p /etc/certidude/authority/{{ authority_name }}/
test -e /etc/certidude/authority/{{ authority_name }}/ca_cert.pem \
 || cat << EOF > /etc/certidude/authority/{{ authority_name }}/ca_cert.pem
{{ session.authority.certificate.blob }}EOF

