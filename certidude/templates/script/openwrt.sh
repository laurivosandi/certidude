#!/bin/sh

# This script can executed on a preconfigured OpenWrt box
# https://lauri.vosandi.com/2017/01/reconfiguring-openwrt-as-dummy-ap.html

# Password protected wireless area
for band in 2ghz 5ghz; do
    uci set wireless.lan$band=wifi-iface
    uci set wireless.lan$band.network=lan
    uci set wireless.lan$band.mode=ap
    uci set wireless.lan$band.device=radio$band
    uci set wireless.lan$band.encryption=psk2
    {% if attributes.protected and attributes.protected.ssid %}
    uci set wireless.lan$band.ssid={{ attrbutes.protected.ssid }}
    {% else %}
    uci set wireless.lan$band.ssid=$(uci get system.@system[0].hostname)-protected
    {% endif %}
    {% if attributes.protected and attributes.protected.psk %}
    uci set wireless.lan$band.key={{ attributes.protected.psk }}
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
    {% if attributes.public and attributes.public.ssid %}
    uci set wireless.guest$band.ssid={{ attrbutes.public.ssid }}
    {% else %}
    uci set wireless.guest$band.ssid=$(uci get system.@system[0].hostname)-public
    {% endif %}
done

