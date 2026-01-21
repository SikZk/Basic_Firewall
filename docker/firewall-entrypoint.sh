#!/bin/bash
set -euo pipefail

LAN_IF="${LAN_IF:-eth2}"
NET1_IF="${NET1_IF:-eth0}"
NET2_IF="${NET2_IF:-eth1}"
LAN_GW="${LAN_GW:-192.168.1.2}"

sysctl -w net.ipv4.ip_forward=1 >/dev/null

ip route replace default via "${LAN_GW}" dev "${LAN_IF}"

iptables -F
iptables -t nat -F
iptables -t mangle -F

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

iptables -A FORWARD -i "${NET1_IF}" -o "${LAN_IF}" -j ACCEPT
iptables -A FORWARD -i "${NET2_IF}" -o "${LAN_IF}" -j ACCEPT
iptables -A FORWARD -i "${LAN_IF}" -o "${NET1_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "${LAN_IF}" -o "${NET2_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o "${LAN_IF}" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.2.0.0/24 -o "${LAN_IF}" -j MASQUERADE

python3 -m http.server 80 --bind 0.0.0.0 >/var/log/firewall-http.log 2>&1 &

exec "$@"
