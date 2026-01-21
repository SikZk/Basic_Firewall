#!/bin/bash
set -euo pipefail

DEFAULT_GW="${DEFAULT_GW:-}"

if [[ -n "${DEFAULT_GW}" ]]; then
  ip route del default || true
  ip route add default via "${DEFAULT_GW}" dev eth0
fi

exec "$@"
