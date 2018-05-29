# See more on http://unmitigatedrisk.com/?p=241 why we're doing this
cat << EOF > /etc/systemd/system/nginx-ocsp-cache.service
{% include "snippets/nginx-ocsp-cache.service" %}EOF

cat << EOF > /etc/systemd/system/nginx-ocsp-cache.timer
{% include "snippets/nginx-ocsp-cache.timer" %}EOF

systemctl enable nginx-ocsp-cache.service
systemctl enable nginx-ocsp-cache.timer
systemctl start nginx-ocsp-cache.service
systemctl start nginx-ocsp-cache.timer
