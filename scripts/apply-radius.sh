#!/usr/bin/env bash
# Переписывает /etc/pam_radius_auth.conf и перезапускает OpenVPN.
# Аргументы через переменные окружения: NPS_HOST NPS_PORT NPS_SECRET NPS_TIMEOUT
set -euo pipefail
: "${NPS_HOST:?}" "${NPS_PORT:?}" "${NPS_SECRET:?}" "${NPS_TIMEOUT:?}"

CONF=/etc/pam_radius_auth.conf
cp "$CONF" "${CONF}.bak.$(date +%s)" 2>/dev/null || true

cat > "$CONF" <<EOF
# server[:port] shared_secret timeout(seconds)
${NPS_HOST}:${NPS_PORT} ${NPS_SECRET} ${NPS_TIMEOUT}
EOF
chmod 600 "$CONF"

systemctl restart openvpn-server@server
