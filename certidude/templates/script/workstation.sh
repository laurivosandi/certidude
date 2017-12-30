# Submit some stats to CA
curl http://{{ authority_name }}/api/signed/{{ common_name }}/attr -X POST -d "\
dmi.product_name=$(cat /sys/class/dmi/id/product_name)&\
dmi.product_serial=$(cat /sys/class/dmi/id/product_serial)&\
kernel=$(uname -sr)&\
dist=$(lsb_release -si) $(lsb_release -sr)&\
cpu=$(cat /proc/cpuinfo  | grep '^model name' | head -n1 | cut -d ":" -f2 | xargs)&\
mem=$(dmidecode -t 17 | grep Size | cut -d ":" -f 2 | cut -d " " -f 2 | paste -sd+ | bc) MB&\
$(for j in /sys/class/net/[we]*; do echo -en if.$(basename $j).ether=$(cat $j/address)\&; done)"

