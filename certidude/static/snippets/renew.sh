curl --cert-status -f -L -H "Content-type: application/pkcs10" \
    --cacert /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem \
    --key /etc/certidude/authority/{{ session.authority.hostname }}/host_key.pem \
    --cert /etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem \
    --data-binary @/etc/certidude/authority/{{ session.authority.hostname }}/host_req.pem \
    -o /etc/certidude/authority/{{ session.authority.hostname }}/host_cert.pem \
    'https://{{ session.authority.hostname }}:8443/api/request/?wait=yes'
