#!/usr/bin/env bash
# Отозвать клиентский сертификат и перегенерировать CRL.
# Использование: revoke-client.sh <cn>
set -euo pipefail
CN="${1:?usage: revoke-client.sh <cn>}"

if [[ ! "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Недопустимое имя пользователя: $CN" >&2
  exit 1
fi

cd /etc/openvpn/easy-rsa
EASYRSA_BATCH=1 ./easyrsa --batch revoke "$CN"
EASYRSA_BATCH=1 ./easyrsa gen-crl
chmod o+r pki/crl.pem
# crl-verify читает файл заново на каждое новое подключение — рестарт
# OpenVPN не требуется. Разрыв уже активной сессии делает панель через
# management-интерфейс (команда kill).
