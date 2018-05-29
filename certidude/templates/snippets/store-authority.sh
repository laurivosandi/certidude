# Save CA certificate
mkdir -p /etc/certidude/authority/{{ session.authority.hostname }}/
test -e /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem \
 || cat << EOF > /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem
{{ session.authority.certificate.blob }}EOF
