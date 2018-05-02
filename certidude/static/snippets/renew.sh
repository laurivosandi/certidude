curl -f -L -H "Content-type: application/pkcs10" \
    --cacert /etc/certidude/authority/{{ authority_name }}/ca_cert.pem \
    --key /etc/certidude/authority/{{ authority_name }}/host_key.pem \
    --cert /etc/certidude/authority/{{ authority_name }}/host_cert.pem \
    --data-binary @/etc/certidude/authority/{{ authority_name }}/host_req.pem \
    -o /etc/certidude/authority/{{ authority_name }}/host_cert.pem \
    'https://{{ authority_name }}:8443/api/request/?wait=yes'
