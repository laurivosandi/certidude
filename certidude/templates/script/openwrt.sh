#!/bin/sh

# This script can be executed on a preconfigured OpenWrt box
# https://lauri.vosandi.com/2017/01/reconfiguring-openwrt-as-dummy-ap.html

# Password protected wireless area
for band in 2ghz 5ghz; do
    uci set wireless.lan$band=wifi-iface
    uci set wireless.lan$band.network=lan
    uci set wireless.lan$band.mode=ap
    uci set wireless.lan$band.device=radio$band
    uci set wireless.lan$band.encryption=psk2
    {% if named_tags and named_tags.wireless and named_tags.wireless.protected and named_tags.wireless.protected.ssid %}
    uci set wireless.lan$band.ssid={{ named_tags.wireless.protected.ssid }}
    {% else %}
    uci set wireless.lan$band.ssid=$(uci get system.@system[0].hostname)-protected
    {% endif %}
    {% if named_tags and named_tags.wireless and named_tags.wireless.protected and named_tags.wireless.protected.psk %}
    uci set wireless.lan$band.key={{ named_tags.wireless.protected.psk }}
    {% else %}
    uci set wireless.lan$band.key=salakala
    {% endif %}
done

# Public wireless area
for band in 2ghz 5ghz; do
    uci set wireless.guest$band=wifi-iface
    uci set wireless.guest$band.network=guest
    uci set wireless.guest$band.mode=ap
    uci set wireless.guest$band.device=radio$band
    uci set wireless.guest$band.encryption=none
    {% if named_tags and named_tags.wireless and named_tags.wireless.public and named_tags.wireless.public.ssid %}
    uci set wireless.guest$band.ssid={{ named_tags.wireless.public.ssid }}
    {% else %}
    uci set wireless.guest$band.ssid=$(uci get system.@system[0].hostname)-public
    {% endif %}
done

