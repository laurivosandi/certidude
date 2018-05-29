# Insert into Fedora trust store. Applies to curl, Firefox, Chrome, Chromium
test -e /etc/pki/ca-trust/source/anchors \
 && ln -s /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem /etc/pki/ca-trust/source/anchors/{{ session.authority.hostname }} \
 && update-ca-trust

# Insert into Ubuntu trust store, only applies to curl
test -e /usr/local/share/ca-certificates/ \
 && ln -f -s /etc/certidude/authority/{{ session.authority.hostname }}/ca_cert.pem /usr/local/share/ca-certificates/{{ session.authority.hostname }}.crt \
 && update-ca-certificates

# Patch Firefox trust store on Ubuntu
if [ -d /usr/lib/firefox ]; then
  if [ ! -h /usr/lib/firefox/libnssckbi.so ]; then
    apt install -y p11-kit p11-kit-modules
    mv /usr/lib/firefox/libnssckbi.so /usr/lib/firefox/libnssckbi.so.bak
    ln -s /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib/firefox/libnssckbi.so
  fi
fi
