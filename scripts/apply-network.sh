#!/usr/bin/env bash
# Переписывает сетевые директивы в server.conf и перезапускает OpenVPN.
# Переменные окружения: VPN_PORT VPN_PROTO VPN_SUBNET VPN_SUBNET_MASK
# SPLIT_ROUTE_NETWORK SPLIT_ROUTE_MASK DNS1 DNS2 POOL_START POOL_END
# Необязательные: DOMAIN_NAME (может быть пустым),
# EXTRA_SPLIT_ROUTES (CIDR через пробел, может быть пустым)
set -euo pipefail

CONF=/etc/openvpn/server/server.conf
: "${VPN_PORT:?}" "${VPN_PROTO:?}" "${VPN_SUBNET:?}" "${VPN_SUBNET_MASK:?}" \
  "${SPLIT_ROUTE_NETWORK:?}" "${SPLIT_ROUTE_MASK:?}" "${DNS1:?}" "${DNS2:?}" \
  "${POOL_START:?}" "${POOL_END:?}"
DOMAIN_NAME="${DOMAIN_NAME:-}"
EXTRA_SPLIT_ROUTES="${EXTRA_SPLIT_ROUTES:-}"

cp "$CONF" "${CONF}.bak.$(date +%s)"

# запоминаем старый порт/протокол — понадобится, чтобы снять старое
# правило ufw, если порт реально меняется
OLD_PORT="$(grep -oP '^port \K\d+' "$CONF" || true)"
OLD_PROTO="$(grep -oP '^proto \K\S+' "$CONF" || true)"

# port / proto / server / ifconfig-pool / route — по одной строке, заменяем как есть
sed -i \
  -e "s#^port .*#port ${VPN_PORT}#" \
  -e "s#^proto .*#proto ${VPN_PROTO}#" \
  -e "s#^server .*#server ${VPN_SUBNET} ${VPN_SUBNET_MASK} nopool#" \
  -e "s#^ifconfig-pool .*#ifconfig-pool ${POOL_START} ${POOL_END}#" \
  -e "s#^push \"route .*#push \"route ${SPLIT_ROUTE_NETWORK} ${SPLIT_ROUTE_MASK}\"#" \
  "$CONF"

# DNS-строки (их может быть 0/1/2) пересобираем явно
grep -v '^push "dhcp-option DNS' "$CONF" > "${CONF}.tmp"
awk -v d1="$DNS1" -v d2="$DNS2" '
  { print }
  /^push "route /   { print "push \"dhcp-option DNS " d1 "\""; print "push \"dhcp-option DNS " d2 "\"" }
' "${CONF}.tmp" > "$CONF"
rm -f "${CONF}.tmp"

# на случай апгрейда со старой версии конфига без ifconfig-pool/client-config-dir
grep -q '^ifconfig-pool ' "$CONF" || sed -i "/^ifconfig-pool-persist/a ifconfig-pool ${POOL_START} ${POOL_END}" "$CONF"
grep -q '^client-config-dir ' "$CONF" || echo "client-config-dir /etc/openvpn/server/ccd" >> "$CONF"
mkdir -p /etc/openvpn/server/ccd

# DOMAIN + дополнительные split-tunnel маршруты — блок между маркерами
# EXTRA_CONFIG_START/END. Если маркеров ещё нет (апгрейд со старой версии
# конфига) — вставляем их сразу после последней строки dhcp-option DNS.
DOMAIN_NAME="$DOMAIN_NAME" EXTRA_SPLIT_ROUTES="$EXTRA_SPLIT_ROUTES" python3 - "$CONF" << 'PY'
import os, re, sys, ipaddress

path = sys.argv[1]
domain = os.environ.get("DOMAIN_NAME", "").strip()
extra_routes_raw = os.environ.get("EXTRA_SPLIT_ROUTES", "").strip()

if domain:
    domain_line = f'push "dhcp-option DOMAIN {domain}"'
else:
    domain_line = "# dhcp-option DOMAIN не задан"

route_lines = []
for cidr in extra_routes_raw.split():
    net = ipaddress.ip_network(cidr, strict=False)
    route_lines.append(f'push "route {net.network_address} {net.netmask}"')
extra_routes_block = "\n".join(route_lines)

new_block = (
    "# --- EXTRA_CONFIG_START (управляется через веб-панель: Settings -> Сеть) ---\n"
    f"{domain_line}\n"
    f"{extra_routes_block}\n"
    "# --- EXTRA_CONFIG_END ---"
)

with open(path) as f:
    content = f.read()

pattern = re.compile(
    r"# --- EXTRA_CONFIG_START.*?# --- EXTRA_CONFIG_END ---", re.S
)
if pattern.search(content):
    content = pattern.sub(new_block, content, count=1)
else:
    # маркеров нет (старый конфиг) — вставляем после последней строки DNS
    lines = content.splitlines()
    last_dns_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith('push "dhcp-option DNS'):
            last_dns_idx = i
    if last_dns_idx is not None:
        lines[last_dns_idx + 1:last_dns_idx + 1] = ["", new_block]
    else:
        lines.append(new_block)
    content = "\n".join(lines) + "\n"

with open(path, "w") as f:
    f.write(content)
PY

# -------------------------------------------------------------------------
# ufw: если порт/протокол реально изменился — снимаем старое правило и
# ставим новое. Без этого смена порта в конфиге ничего бы не дала: старый
# порт остался бы открыт, а новый — закрыт файрволом самого сервера.
# -------------------------------------------------------------------------
if command -v ufw >/dev/null 2>&1; then
  if [[ -n "$OLD_PORT" && -n "$OLD_PROTO" ]] && \
     [[ "$OLD_PORT" != "$VPN_PORT" || "$OLD_PROTO" != "$VPN_PROTO" ]]; then
    while true; do
      rule_num="$(ufw status numbered | grep 'OpenVPN' | head -n1 | grep -oP '^\[\s*\K[0-9]+' || true)"
      [[ -z "$rule_num" ]] && break
      ufw --force delete "$rule_num" >/dev/null
    done
    ufw allow "${VPN_PORT}/${VPN_PROTO}" comment "OpenVPN"
    ufw reload
  fi
fi

systemctl restart openvpn-server@server
