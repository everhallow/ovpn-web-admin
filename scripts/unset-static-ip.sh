#!/usr/bin/env bash
# Снять статический IP с пользователя. Использование: unset-static-ip.sh <cn>
set -euo pipefail
CN="${1:?usage: unset-static-ip.sh <cn>}"

if [[ ! "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Недопустимое имя пользователя: $CN" >&2
  exit 1
fi

CCD_DIR="${CCD_DIR:-/etc/openvpn/server/ccd}"
rm -f "${CCD_DIR}/${CN}"
