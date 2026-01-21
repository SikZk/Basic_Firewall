#!/bin/bash
set -euo pipefail

# Helper function to find interface by checking which one has an IP in the given subnet
find_if_by_subnet() {
  local subnet_prefix="$1"
  # List all interfaces, look for one that has an IP starting with the prefix
  # filters out lo and possibly docker0 if present, though inside container usually just ethX
  ip -o -4 addr show | grep " ${subnet_prefix}" | awk '{print $2}' | head -n1
}

# 172.29.200.0/24 -> LAN
LAN_IF="$(find_if_by_subnet "172.29.200")"
# 172.29.101.0/24 -> NET1
NET1_IF="$(find_if_by_subnet "172.29.101")"
# 172.29.102.0/24 -> NET2
NET2_IF="$(find_if_by_subnet "172.29.102")"

# Fallbacks in case detection fails (though it really shouldn't if networks are attached)
LAN_IF="${LAN_IF:-eth2}"
NET1_IF="${NET1_IF:-eth0}"
NET2_IF="${NET2_IF:-eth1}"
LAN_GW="${LAN_GW:-172.29.200.1}"

echo "Detected LAN_IF=${LAN_IF}, NET1_IF=${NET1_IF}, NET2_IF=${NET2_IF}"
echo "Setting default gateway to ${LAN_GW} via ${LAN_IF}"

ip route replace default via "${LAN_GW}" dev "${LAN_IF}"

iptables -F
iptables -t nat -F
iptables -t mangle -F

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# Allow traffic forwarding between networks
# CAUTION: This logic assumes successful detection.
if [[ -n "${NET1_IF}" && -n "${LAN_IF}" ]]; then
  iptables -A FORWARD -i "${NET1_IF}" -o "${LAN_IF}" -j ACCEPT
  iptables -A FORWARD -i "${LAN_IF}" -o "${NET1_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

if [[ -n "${NET2_IF}" && -n "${LAN_IF}" ]]; then
  iptables -A FORWARD -i "${NET2_IF}" -o "${LAN_IF}" -j ACCEPT
  iptables -A FORWARD -i "${LAN_IF}" -o "${NET2_IF}" -m state --state ESTABLISHED,RELATED -j ACCEPT
fi

iptables -t nat -A POSTROUTING -s 172.29.101.0/24 -o "${LAN_IF}" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.29.102.0/24 -o "${LAN_IF}" -j MASQUERADE

python3 -m http.server 80 --bind 0.0.0.0 >/var/log/firewall-http.log 2>&1 &

exec "$@"