# Configure port tagging
uci set network.lan.ifname='eth0.3' # Protected network VLAN3 tagged
uci set network.guest.ifname='eth0.4' # Public network VLAN4 tagged

# Configure wireless networks
for band in 2ghz 5ghz; do
    uci delete wireless.radio$band.disabled
    uci set wireless.radio$band.country=EE

    uci set wireless.guest$band=wifi-iface
    uci set wireless.guest$band.network=guest
    uci set wireless.guest$band.mode=ap
    uci set wireless.guest$band.device=radio$band
    uci set wireless.guest$band.encryption=none
    uci set wireless.guest$band.ssid="k-space.ee guest"

    uci set wireless.lan$band=wifi-iface
    uci set wireless.lan$band.network=lan
    uci set wireless.lan$band.mode=ap
    uci set wireless.lan$band.device=radio$band
    uci set wireless.lan$band.encryption=psk2+ccmp
    uci set wireless.lan$band.ssid="k-space protected"
    uci set wireless.lan$band.key="salakala"

done

# Add Lauri's Yubikey
cat > /etc/dropbear/authorized_keys << \EOF
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCb4iqSrJrA13ygAZTZb6ElPsMXrlXXrztxt3bcKuEbAiWOm9lR17puRLMZbM2tvAW+iwsDHfQAs0E6HDprP68nt+SGkQvItUtYeJBWDI405DbRodmDMySahmb6o6S3sqI4vryydOg1G+Z0DITksZzp91Ow+C++emk6aqWfXh7xATexCvKphfwXrBL+MDIwx6drIiN0FD08yd/zxGAlcQpR8o6uecmXdk32wL5W3+qqwbJrLjZmOweij5KSXuEARuQhM20KXzYzzQIAKqhIoALRSEX31L0bwxOqfVaotzk4TWKJSeetEhBOd7PtH0ZrmOHF+B20Ym+V3UkRY5P4calF
EOF

# Set root password to 'salakala'
sed -i 's|^root::|root:$1$S0wGaZqK$fzEzb0WTC5.WHm2Fz9UI9.:|' /etc/shadow

