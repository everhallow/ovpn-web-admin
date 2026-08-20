#!/usr/bin/env bash
# =========================================================================
# install.sh — установка OpenVPN + аутентификация через RADIUS(NPS) + веб-панель
# Ubuntu 22.04. Запускать от root: sudo ./install.sh
# Параметры берутся из install.conf (см. install.conf.example)
# =========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/install.conf"

if [[ $EUID -ne 0 ]]; then
  echo "Запускайте от root (sudo ./install.sh)" >&2
  exit 1
fi

if [[ ! -f "$CONF_FILE" ]]; then
  echo "Не найден install.conf. Скопируйте install.conf.example -> install.conf и заполните." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONF_FILE"

for var in VPN_PROTO VPN_PORT VPN_SUBNET VPN_SUBNET_MASK SPLIT_ROUTE_NETWORK \
           SPLIT_ROUTE_MASK DNS1 DNS2 NPS_HOST NPS_AUTH_PORT NPS_SECRET NPS_TIMEOUT \
           PANEL_PORT PANEL_ADMIN_USER PANEL_ADMIN_PASS PANEL_ALLOWED_CIDR \
           DEFAULT_REMOTE_HOST DEFAULT_REMOTE_PORT SERVER_CN ENABLE_NAT INTERNAL_IFACE; do
  if [[ -z "${!var:-}" ]]; then
    echo "Параметр $var не задан в install.conf" >&2
    exit 1
  fi
done

# DOMAIN_NAME и EXTRA_SPLIT_ROUTES необязательны — если их нет в install.conf
# (например, старый install.conf от предыдущей версии), считаем пустыми.
DOMAIN_NAME="${DOMAIN_NAME:-}"
EXTRA_SPLIT_ROUTES="${EXTRA_SPLIT_ROUTES:-}"

echo "==> Обновляю пакеты и ставлю зависимости"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  openvpn easy-rsa libpam-radius-auth ufw \
  python3-venv python3-pip sqlite3 curl

echo "==> Ищу путь к плагину openvpn-plugin-auth-pam.so"
AUTH_PAM_PLUGIN_PATH="$(dpkg -L openvpn | grep -m1 'openvpn-plugin-auth-pam.so' || true)"
if [[ -z "$AUTH_PAM_PLUGIN_PATH" ]]; then
  # запасные варианты на случай другого пути в пакете
  for candidate in \
    /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
    /usr/lib/openvpn/openvpn-plugin-auth-pam.so \
    /usr/lib/aarch64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so; do
    [[ -f "$candidate" ]] && AUTH_PAM_PLUGIN_PATH="$candidate" && break
  done
fi
if [[ -z "$AUTH_PAM_PLUGIN_PATH" ]]; then
  echo "Не удалось найти openvpn-plugin-auth-pam.so, проверьте установку пакета openvpn" >&2
  exit 1
fi
echo "    найден: $AUTH_PAM_PLUGIN_PATH"

# -------------------------------------------------------------------------
# PKI (easy-rsa)
# -------------------------------------------------------------------------
echo "==> Инициализирую PKI (easy-rsa)"
mkdir -p /etc/openvpn/server
if [[ ! -d /etc/openvpn/easy-rsa ]]; then
  make-cadir /etc/openvpn/easy-rsa
fi
cd /etc/openvpn/easy-rsa

if [[ ! -f pki/ca.crt ]]; then
  ./easyrsa init-pki
  EASYRSA_BATCH=1 ./easyrsa --batch build-ca nopass
fi

if [[ ! -f "pki/issued/${SERVER_CN}.crt" ]]; then
  EASYRSA_BATCH=1 ./easyrsa --batch build-server-full "$SERVER_CN" nopass
fi

if [[ ! -f pki/dh.pem ]]; then
  ./easyrsa gen-dh
fi

if [[ ! -f pki/crl.pem ]]; then
  ./easyrsa gen-crl
fi
chmod o+r /etc/openvpn/easy-rsa/pki/crl.pem

if [[ ! -f /etc/openvpn/server/ta.key ]]; then
  openvpn --genkey secret /etc/openvpn/server/ta.key
fi

mkdir -p /etc/openvpn/server/ccd

# -------------------------------------------------------------------------
# Разбивка пула: ~70% адресов под динамическую выдачу, остаток резервируем
# под статические назначения через панель (первый хост подсети — это сам
# сервер, его не трогаем).
# -------------------------------------------------------------------------
echo "==> Считаю границы динамического пула для ${VPN_SUBNET}/${VPN_SUBNET_MASK}"
read -r POOL_START POOL_END <<< "$(python3 - "$VPN_SUBNET" "$VPN_SUBNET_MASK" <<'PY'
import sys, ipaddress
net = ipaddress.ip_network(f"{sys.argv[1]}/{sys.argv[2]}", strict=False)
hosts = list(net.hosts())[1:]  # первый хост зарезервирован под сам сервер
if len(hosts) < 4:
    start, end = hosts[0], hosts[-1]
else:
    split = max(1, int(len(hosts) * 0.7))
    start, end = hosts[0], hosts[split]
print(start, end)
PY
)"
echo "    динамический пул: ${POOL_START} - ${POOL_END} (остальное свободно под статику)"

# -------------------------------------------------------------------------
# EXTRA_CONFIG: dhcp-option DOMAIN + дополнительные split-tunnel маршруты
# -------------------------------------------------------------------------
if [[ -n "$DOMAIN_NAME" ]]; then
  DOMAIN_PUSH_LINE="push \"dhcp-option DOMAIN ${DOMAIN_NAME}\""
else
  DOMAIN_PUSH_LINE="# dhcp-option DOMAIN не задан"
fi

EXTRA_ROUTES_BLOCK=""
if [[ -n "$EXTRA_SPLIT_ROUTES" ]]; then
  EXTRA_ROUTES_BLOCK="$(python3 - "$EXTRA_SPLIT_ROUTES" << 'PY'
import sys, ipaddress
lines = []
for cidr in sys.argv[1].split():
    net = ipaddress.ip_network(cidr, strict=False)
    lines.append(f'push "route {net.network_address} {net.netmask}"')
print("\n".join(lines))
PY
)"
fi

# -------------------------------------------------------------------------
# server.conf: base + auth-блок (PAP)
# -------------------------------------------------------------------------
echo "==> Пишу /etc/openvpn/server/server.conf"

AUTH_BLOCK_CONTENT="$(sed -e "s#__AUTH_PAM_PLUGIN_PATH__#${AUTH_PAM_PLUGIN_PATH}#g" \
  "${SCRIPT_DIR}/templates/auth-block-pap.conf.tpl")"

sed \
  -e "s#__VPN_PORT__#${VPN_PORT}#g" \
  -e "s#__VPN_PROTO__#${VPN_PROTO}#g" \
  -e "s#__SERVER_CN__#${SERVER_CN}#g" \
  -e "s#__VPN_SUBNET__#${VPN_SUBNET}#g" \
  -e "s#__VPN_SUBNET_MASK__#${VPN_SUBNET_MASK}#g" \
  -e "s#__POOL_START__#${POOL_START}#g" \
  -e "s#__POOL_END__#${POOL_END}#g" \
  -e "s#__SPLIT_ROUTE_NETWORK__#${SPLIT_ROUTE_NETWORK}#g" \
  -e "s#__SPLIT_ROUTE_MASK__#${SPLIT_ROUTE_MASK}#g" \
  -e "s#__DNS1__#${DNS1}#g" \
  -e "s#__DNS2__#${DNS2}#g" \
  "${SCRIPT_DIR}/templates/server-base.conf.tpl" > /etc/openvpn/server/server.conf.tmp

# вставляем многострочные блоки вместо плейсхолдеров (через python —
# надёжнее, чем sed, т.к. блоки могут содержать спецсимволы sed/переносы строк)
python3 - "$AUTH_BLOCK_CONTENT" "$DOMAIN_PUSH_LINE" "$EXTRA_ROUTES_BLOCK" << 'PY'
import sys
auth_block, domain_line, extra_routes = sys.argv[1], sys.argv[2], sys.argv[3]
path = "/etc/openvpn/server/server.conf.tmp"
with open(path) as f:
    content = f.read()
content = content.replace("__AUTH_BLOCK__", auth_block)
content = content.replace("__DOMAIN_PUSH_LINE__", domain_line)
content = content.replace("__EXTRA_ROUTES_BLOCK__", extra_routes)
with open("/etc/openvpn/server/server.conf", "w") as f:
    f.write(content)
PY
rm -f /etc/openvpn/server/server.conf.tmp

# -------------------------------------------------------------------------
# PAM + RADIUS
# -------------------------------------------------------------------------
echo "==> Настраиваю pam_radius_auth (NPS: ${NPS_HOST}:${NPS_AUTH_PORT})"
sed \
  -e "s#__NPS_HOST__#${NPS_HOST}#g" \
  -e "s#__NPS_AUTH_PORT__#${NPS_AUTH_PORT}#g" \
  -e "s#__NPS_SECRET__#${NPS_SECRET}#g" \
  -e "s#__NPS_TIMEOUT__#${NPS_TIMEOUT}#g" \
  "${SCRIPT_DIR}/templates/pam_radius_auth.conf.tpl" > /etc/pam_radius_auth.conf
chmod 600 /etc/pam_radius_auth.conf

cp "${SCRIPT_DIR}/templates/pam.d.openvpn.tpl" /etc/pam.d/openvpn

# -------------------------------------------------------------------------
# Доп. проверка "логин == CN сертификата" (см. auth-user-pass-verify в
# server-base.conf.tpl)
# -------------------------------------------------------------------------
cp "${SCRIPT_DIR}/templates/check-cn-username.sh" /etc/openvpn/server/check-cn-username.sh
chmod 755 /etc/openvpn/server/check-cn-username.sh

# -------------------------------------------------------------------------
# Логирование подключений (client-connect/client-disconnect -> JSON-lines
# для веб-панели, вкладка "Логирование")
# -------------------------------------------------------------------------
cp "${SCRIPT_DIR}/templates/client-connect.sh" /etc/openvpn/server/client-connect.sh
cp "${SCRIPT_DIR}/templates/client-disconnect.sh" /etc/openvpn/server/client-disconnect.sh
chmod 755 /etc/openvpn/server/client-connect.sh /etc/openvpn/server/client-disconnect.sh
mkdir -p /var/log/openvpn
touch /var/log/openvpn/connections.log
chmod 644 /var/log/openvpn/connections.log

cp "${SCRIPT_DIR}/templates/logrotate-openvpn.tpl" /etc/logrotate.d/openvpn-panel

# -------------------------------------------------------------------------
# sysctl / forwarding / NAT
# -------------------------------------------------------------------------
echo "==> Включаю IPv4 forwarding"
if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1

if [[ "${ENABLE_NAT}" == "yes" ]]; then
  echo "==> Включаю MASQUERADE для ${SPLIT_ROUTE_NETWORK}/${SPLIT_ROUTE_MASK} через ${INTERNAL_IFACE}"
  cat > /etc/openvpn/server/nat-up.sh <<EOF
#!/bin/sh
iptables -t nat -C POSTROUTING -s ${VPN_SUBNET}/${VPN_SUBNET_MASK} -o ${INTERNAL_IFACE} -j MASQUERADE 2>/dev/null || \\
iptables -t nat -A POSTROUTING -s ${VPN_SUBNET}/${VPN_SUBNET_MASK} -o ${INTERNAL_IFACE} -j MASQUERADE
EOF
  chmod +x /etc/openvpn/server/nat-up.sh
  /etc/openvpn/server/nat-up.sh
  # чтобы правило переживало перезагрузку — добавим systemd unit
  cat > /etc/systemd/system/ovpn-nat.service <<EOF
[Unit]
Description=OpenVPN NAT rule
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/openvpn/server/nat-up.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ovpn-nat.service
fi

# -------------------------------------------------------------------------
# UFW
# -------------------------------------------------------------------------
echo "==> Настраиваю ufw"
ufw allow "${VPN_PORT}/${VPN_PROTO}" comment "OpenVPN"
ufw allow OpenSSH || true
# Панель доступна с адресов из PANEL_ALLOWED_CIDR (список сетей через
# пробел, по умолчанию весь RFC1918), не привязана к VPN-туннелю.
# Значение можно поменять позже через саму панель — Settings -> "Доступ
# к панели" — либо руками через ufw.
for cidr in ${PANEL_ALLOWED_CIDR}; do
  ufw allow from "${cidr}" to any port "${PANEL_PORT}" proto tcp comment "ovpn-panel-acl"
done
ufw --force enable

# -------------------------------------------------------------------------
# Запуск OpenVPN
# -------------------------------------------------------------------------
echo "==> Запускаю OpenVPN"
systemctl enable --now "openvpn-server@server"

# -------------------------------------------------------------------------
# Веб-панель
# -------------------------------------------------------------------------
echo "==> Разворачиваю веб-панель"
PANEL_DIR=/opt/ovpn-panel
mkdir -p "$PANEL_DIR"
cp -r "${SCRIPT_DIR}/panel/"* "$PANEL_DIR/"
cp -r "${SCRIPT_DIR}/scripts" "$PANEL_DIR/scripts"
chmod +x "$PANEL_DIR"/scripts/*.sh

python3 -m venv "$PANEL_DIR/venv"
"$PANEL_DIR/venv/bin/pip" install --upgrade pip
"$PANEL_DIR/venv/bin/pip" install -r "$PANEL_DIR/requirements.txt"

echo "==> Определяю внешний сетевой интерфейс для виджета нагрузки"
NET_IFACE="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)"
[[ -z "$NET_IFACE" ]] && NET_IFACE="$INTERNAL_IFACE"
echo "    интерфейс: ${NET_IFACE}"

mkdir -p "$PANEL_DIR/instance"
cat > "$PANEL_DIR/instance/settings.env" <<EOF
EASYRSA_DIR="/etc/openvpn/easy-rsa"
SERVER_CN="${SERVER_CN}"
TA_KEY_PATH="/etc/openvpn/server/ta.key"
SERVER_CONF_PATH="/etc/openvpn/server/server.conf"
PAM_RADIUS_CONF_PATH="/etc/pam_radius_auth.conf"
CCD_DIR="/etc/openvpn/server/ccd"
OPENVPN_STATUS_PATH="/etc/openvpn/server/openvpn-status.log"
CONNECTIONS_LOG_PATH="/var/log/openvpn/connections.log"
OPENVPN_APP_LOG_PATH="/var/log/openvpn/server.log"
MGMT_HOST="127.0.0.1"
MGMT_PORT="7505"
PANEL_PORT="${PANEL_PORT}"
PANEL_DB="${PANEL_DIR}/instance/panel.db"
FLASK_SECRET="$(openssl rand -hex 32)"
DEFAULT_REMOTE_HOST="${DEFAULT_REMOTE_HOST}"
DEFAULT_REMOTE_PORT="${DEFAULT_REMOTE_PORT}"
DEFAULT_PROTO="${VPN_PROTO}"
DEFAULT_PANEL_ALLOWED_CIDR="${PANEL_ALLOWED_CIDR}"
DEFAULT_NPS_HOST="${NPS_HOST}"
DEFAULT_NPS_PORT="${NPS_AUTH_PORT}"
DEFAULT_NPS_SECRET="${NPS_SECRET}"
DEFAULT_NPS_TIMEOUT="${NPS_TIMEOUT}"
NET_IFACE="${NET_IFACE}"
EOF
chmod 600 "$PANEL_DIR/instance/settings.env"

# Первичная инициализация БД панели (создаёт admin-пользователя и заполняет
# настройки значениями из install.conf). Явно прокидываем все DEFAULT_*
# переменные через префикс команды — они нужны init_db.py именно сейчас,
# в момент первого запуска, а не только в settings.env для systemd.
PANEL_ADMIN_USER="$PANEL_ADMIN_USER" \
PANEL_ADMIN_PASS="$PANEL_ADMIN_PASS" \
DEFAULT_REMOTE_HOST="$DEFAULT_REMOTE_HOST" \
DEFAULT_REMOTE_PORT="$DEFAULT_REMOTE_PORT" \
DEFAULT_PROTO="$VPN_PROTO" \
DEFAULT_PANEL_ALLOWED_CIDR="$PANEL_ALLOWED_CIDR" \
DEFAULT_NPS_HOST="$NPS_HOST" \
DEFAULT_NPS_PORT="$NPS_AUTH_PORT" \
DEFAULT_NPS_SECRET="$NPS_SECRET" \
DEFAULT_NPS_TIMEOUT="$NPS_TIMEOUT" \
  "$PANEL_DIR/venv/bin/python" "$PANEL_DIR/init_db.py"

cat > /etc/systemd/system/ovpn-panel.service <<EOF
[Unit]
Description=OpenVPN admin web panel
After=network.target openvpn-server@server.service

[Service]
Type=simple
WorkingDirectory=${PANEL_DIR}
EnvironmentFile=${PANEL_DIR}/instance/settings.env
ExecStart=${PANEL_DIR}/venv/bin/gunicorn -w 1 --threads 4 -b 0.0.0.0:${PANEL_PORT} app:app
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ovpn-panel.service

SERVER_INTERNAL_IP="$(ip -4 addr show "$INTERNAL_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -n1)"

echo ""
echo "======================================================================"
echo " Готово."
echo " OpenVPN слушает: ${VPN_PORT}/${VPN_PROTO}"
echo " Динамический пул адресов: ${POOL_START} - ${POOL_END}"
echo " Веб-панель: http://${SERVER_INTERNAL_IP:-<внутренний_IP_сервера>}:${PANEL_PORT}"
echo " Доступ к панели разрешён только с адресов: ${PANEL_ALLOWED_CIDR}"
echo " Логин панели: ${PANEL_ADMIN_USER}"
echo ""
echo " ВАЖНО, что нужно сделать руками:"
echo " 1) На NPS добавьте RADIUS-клиента с адресом этого сервера и тем же"
echo "    shared secret, что в install.conf (NPS_SECRET). Позже эти данные"
echo "    можно поменять прямо в панели (Settings -> RADIUS)."
echo " 2) Проверьте, что порт ${VPN_PORT}/${VPN_PROTO} действительно"
echo "    проброшен на эту машину на вашем NAT-шлюзе/security group."
echo " 3) Если ENABLE_NAT=no — добавьте на ядре сети статический маршрут:"
echo "    ${VPN_SUBNET}/${VPN_SUBNET_MASK} -> внутренний IP этого сервера."
echo " 4) Убедитесь, что ваш браузер выходит в сеть с адресом из"
echo "    ${PANEL_ALLOWED_CIDR} — иначе панель будет недоступна (это"
echo "    осознанное ограничение, не связанное с VPN-туннелем)."
echo "======================================================================"
