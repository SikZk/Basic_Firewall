#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${EXTERNAL_GW:-}" ]]; then
  ip route replace default via "${EXTERNAL_GW}"
fi

exec "$@"
