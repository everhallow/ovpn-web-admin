#!/usr/bin/env bash
# Выпустить клиентский сертификат. Использование: issue-client.sh <cn>
set -euo pipefail
CN="${1:?usage: issue-client.sh <cn>}"

# CN — только безопасные символы
if [[ ! "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Недопустимое имя пользователя: $CN" >&2
  exit 1
fi

cd /etc/openvpn/easy-rsa
EASYRSA_BATCH=1 ./easyrsa --batch build-client-full "$CN" nopass
