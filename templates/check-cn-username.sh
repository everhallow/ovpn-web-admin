#!/usr/bin/env bash
# Вызывается OpenVPN через auth-user-pass-verify (метод via-env) на КАЖДОЕ
# подключение, в дополнение к RADIUS-проверке через plugin. Если введённый
# логин не совпадает с CN клиентского сертификата — коннект отклоняется,
# даже если RADIUS/NPS сам по себе принял бы этот логин/пароль.
#
# OpenVPN передаёт сюда через переменные окружения:
#   $common_name — CN клиентского сертификата (из TLS-рукопожатия)
#   $username    — логин, который ввёл клиент (via-env)
#
# Сравнение регистронезависимое (AD-логины по факту регистронезависимы),
# чтобы не ловить ложные отказы из-за разного капса при вводе.
set -euo pipefail

cn_lower="$(echo "${common_name:-}" | tr '[:upper:]' '[:lower:]')"
user_lower="$(echo "${username:-}" | tr '[:upper:]' '[:lower:]')"

if [[ -z "$cn_lower" || -z "$user_lower" ]]; then
  logger -t openvpn-cn-check "reject: пустой common_name или username (cn='${common_name:-}' user='${username:-}')"
  exit 1
fi

if [[ "$cn_lower" != "$user_lower" ]]; then
  logger -t openvpn-cn-check "reject: логин '${username}' не совпадает с CN сертификата '${common_name}'"
  exit 1
fi

exit 0
