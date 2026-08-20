#!/usr/bin/env bash
# Назначить статический IP пользователю. Использование:
#   set-static-ip.sh <cn> <ip> <mask>
# Изменение подхватывается на следующее подключение клиента, рестарт
# OpenVPN не требуется (ccd читается заново при каждом новом соединении).
set -euo pipefail
CN="${1:?usage: set-static-ip.sh <cn> <ip> <mask>}"
IP="${2:?}"
MASK="${3:?}"

if [[ ! "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Недопустимое имя пользователя: $CN" >&2
  exit 1
fi

CCD_DIR="${CCD_DIR:-/etc/openvpn/server/ccd}"
mkdir -p "$CCD_DIR"
echo "ifconfig-push ${IP} ${MASK}" > "${CCD_DIR}/${CN}"
