#!/usr/bin/env bash
# Переписывает ufw-правила доступа к веб-панели. НЕ требует и не делает
# рестарт OpenVPN — текущие VPN-сессии не затрагиваются.
# Переменные окружения: PANEL_PORT ALLOWED_CIDR (список сетей через пробел)
set -euo pipefail
: "${PANEL_PORT:?}" "${ALLOWED_CIDR:?}"

for cidr in ${ALLOWED_CIDR}; do
  if [[ ! "$cidr" =~ ^[0-9./]+$ ]]; then
    echo "Недопустимый CIDR: $cidr" >&2
    exit 1
  fi
done

# Удаляем все прежние правила панели (помечены комментарием ovpn-panel-acl)
while true; do
  rule_num="$(ufw status numbered | grep 'ovpn-panel-acl' | head -n1 | grep -oP '^\[\s*\K[0-9]+' || true)"
  [[ -z "$rule_num" ]] && break
  ufw --force delete "$rule_num" >/dev/null
done

for cidr in ${ALLOWED_CIDR}; do
  ufw allow from "$cidr" to any port "$PANEL_PORT" proto tcp comment 'ovpn-panel-acl'
done
ufw reload
