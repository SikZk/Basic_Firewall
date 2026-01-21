#!/bin/bash
set -euo pipefail

DEFAULT_GW="${DEFAULT_GW:-}"
DEFAULT_DNS="${DEFAULT_DNS:-1.1.1.1}"
if [[ -n "${DEFAULT_GW}" ]]; then
  ip route del default || true
  ip route add default via "${DEFAULT_GW}" dev eth0
fi
case "${SERVICE_NAME:-}" in
  host1) ip route replace default via 172.29.101.1 ;;
  host2) ip route replace default via 172.29.102.1 ;;
  *) : ;; # do nothing
esac
if [[ -n "${DEFAULT_DNS}" ]]; then
  printf "nameserver %s\n" "${DEFAULT_DNS}" > /etc/resolv.conf
fi

exec "$@"
