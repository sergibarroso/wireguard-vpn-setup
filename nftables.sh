#!/bin/bash

nft="/sbin/nft";

# ruleset, masquerade and full reject support are available starting with Linux Kernel 3.18
${nft} flush ruleset;

export LAN_IN=enp3s6
export LAN_ML=enp2s0
export WAN=ppp0
LAN_INLOCALNET=192.168.1.0/24
LAN_MLNET=10.52.0.0/14
MLIP=10.54.1.101
TORRENT_PORT_WAN=55414
TRACKER_TORRENT_PORT_WAN=4949
TORRENT_PORT_LAN=55413

MAC[2]=00:23:45:67:89:ab
...
MAC[20]=00:fe:dc:ba:98:76

${nft} -f /etc/nftables/ipv4-filter;
${nft} -f /etc/nftables/ipv4-nat;

# BANNED
${nft} add rule filter input meta iifname ${WAN} ip saddr 121.12.242.43 drop;

# Drop locals from internet
${nft} add rule filter input meta iifname ${WAN} ip saddr \
        { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 } drop;

# Drop invalid
${nft} add rule filter input ct state invalid drop;

${nft} add rule filter input meta iif lo ct state new accept;

${nft} add rule filter input meta iif ${LAN_ML} ip saddr ${LAN_MLNET} ct state new accept;
${nft} add rule filter input meta iif ${LAN_IN} ip saddr ${LAN_INLOCALNET} ct state new accept;

${nft} add rule filter input ip protocol tcp tcp dport \
        { ${TORRENT_PORT_LAN}, ${TORRENT_PORT_WAN}, \
                ${TRACKER_TORRENT_PORT_WAN} } ct state new accept;
${nft} add rule filter input ip protocol udp udp dport \
        { ${TORRENT_PORT_LAN}, ${TORRENT_PORT_WAN}, \
                ${TRACKER_TORRENT_PORT_WAN} } ct state new accept;

${nft} add rule filter input meta iifname ${WAN} ip protocol tcp ct state new tcp dport 80 accept;

# torrent port forwarding example
${nft} add rule nat prerouting meta iifname ${WAN} tcp dport ${TORRENT_PORT_LAN} \
        dnat 192.168.1.10:${TORRENT_PORT_LAN}

${nft} add rule filter forward meta iifname ${WAN} meta oif ${LAN_IN} ip daddr 192.168.1.10 \
        tcp dport ${TORRENT_PORT_LAN} ct state new accept;

${nft} add rule filter input ip saddr != ${LAN_INLOCALNET} ct state new drop;
${nft} add rule filter forward meta iif ${LAN_ML} ct state new drop;
${nft} add rule filter forward meta iifname ${WAN} ct state new drop;


${nft} add rule filter input ct state established,related accept;

${nft} add rule nat postrouting oif ${LAN_ML} ip saddr ${LAN_INLOCALNET} snat ${MLIP};
${nft} add rule nat postrouting oifname ${WAN} ip saddr ${LAN_INLOCALNET} masquerade;

${nft} add rule filter forward ct state established,related accept;

# Give internet access to internal LAN addresses
for i in {2..20}
do
if grep 1 /var/www/myhost/htdocs/payment/192.168.1.$i > /dev/null;
then
        ${nft} add rule filter forward ether saddr ${MAC[$i]} ip saddr 192.168.1.$i \
                ct state new accept;
        echo ACCEPT 192.168.1.$i ALL;
else
        ${nft} add rule filter forward ether saddr ${MAC[$i]} ip saddr 192.168.1.$i \
                meta oif ${LAN_ML} ct state new accept;
        echo ACCEPT 192.168.1.$i ${LAN_ML};
fi
done



# Policies
${nft} add rule filter input drop;
${nft} add rule filter forward drop;
${nft} add rule filter output accept;

/etc/init.d/nftables save;