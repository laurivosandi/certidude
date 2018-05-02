test -e /etc/pki/ca-trust/source/anchors \
 && ln -s /etc/certidude/authority/{{ authority_name }}/ca_cert.pem /etc/pki/ca-trust/source/anchors/{{ authority_name }} \
 && update-ca-trust
test -e /usr/local/share/ca-certificates/ \
 && ln -s /etc/certidude/authority/{{ authority_name }}/ca_cert.pem /usr/local/share/ca-certificates/{{ authority_name }}.crt \
 && update-ca-certificates

