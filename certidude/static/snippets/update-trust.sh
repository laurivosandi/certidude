# Insert into Fedora trust store. Applies to curl, Firefox, Chrome, Chromium
test -e /etc/pki/ca-trust/source/anchors \
 && ln -s /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem /etc/pki/ca-trust/source/anchors/{{ session.authority.hostname }} \
 && update-ca-trust

# Insert into Ubuntu trust store, only applies to curl
test -e /usr/local/share/ca-certificates/ \
 && ln -s /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem /usr/local/share/ca-certificates/{{ session.authority.hostname }}.crt \
 && update-ca-certificates
