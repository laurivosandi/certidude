Token for {{ user.name }}

{% if issuer == user %}
Token has been issued for {{ user }} for retrieving profile from link below.
{% else %}
{{ issuer }} has provided {{ user }} a token for retrieving
profile from the link below.
{% endif %}

{% if config.BUNDLE_FORMAT == "ovpn" %}
To set up OpenVPN for your device:

* for Android install [OpenVPN Connect](https://play.google.com/store/apps/details?id=de.blinkt.openvpn) app. After importing the OpenVPN profile in OpenVPN application and delete the downloaded .ovpn file.
* for iOS device install [OpenVPN Connect](https://itunes.apple.com/us/app/openvpn-connect/id590379981) app. Tap on the token URL below, it should be automatically opened with OpenVPN Connect app. Tap connect to establish connection.
* for Mac OS X download [Tunnelblick](https://tunnelblick.net/downloads.html)
* for Ubuntu install [OpenVPN plugin for NetworkManager](apt://network-manager-openvpn-gnome), click on the token link below to download OpenVPN profile. Click on the NetworkManager icon, select "Edit Connections...", click on "Add" button to add a connection. From the dropdown menu select "Import a saved VPN configuration..." and supply the downloaded file.
* for Fedora install OpenVPN plugin for NetworkManager. Open network settings, add connection and select "Import a saved VPN configuration...". Supply the file retrieved via the token URL below.
* for Windows install OpenVPN community edition from [here](https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.14-I601-x86_64.exe) and TAP driver from [here](https://swupdate.openvpn.org/community/releases/tap-windows-9.21.2.exe)
{% endif %}

Click [here]({{ config.TOKEN_URL }}?{{ args }}) to claim the token.
Token is usable until {{  token_expires }}{% if token_timezone %} ({{ token_timezone }} time){% endif %}.

