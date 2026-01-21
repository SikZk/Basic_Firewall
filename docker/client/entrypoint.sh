#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${FIREWALL_GW:-}" ]]; then
  ip route replace default via "${FIREWALL_GW}"
fi

exec "$@"
