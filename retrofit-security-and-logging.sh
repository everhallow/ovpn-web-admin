#!/usr/bin/env bash
# =========================================================================
# retrofit-security-and-logging.sh — накатывает на УЖЕ работающий сервер
# (без переустановки) две функции, которые появились после первоначальной
# установки:
#   1) проверка "логин == CN сертификата" (auth-user-pass-verify)
#   2) логирование подключений пользователей для вкладки "Логирование"
#      в панели (client-connect/client-disconnect)
#
# ИДЕМПОТЕНТЕН: можно запускать сколько угодно раз, ничего не задублирует
# в server.conf — каждая директива добавляется, только если её ещё нет.
# Это специально сделано так, чтобы не наступить на грабли "добавили
# client-connect/client-disconnect, а script-security 2 забыли — и всё
# сломалось", потому что скрипт сам проверяет и добавляет все необходимые
# зависимые директивы вместе, а не по отдельности.
#
# Запускать от root, из корня проекта: sudo ./retrofit-security-and-logging.sh
# =========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/openvpn/server/server.conf

if [[ $EUID -ne 0 ]]; then
  echo "Запускайте от root (sudo ./retrofit-security-and-logging.sh)" >&2
  exit 1
fi

if [[ ! -f "$CONF" ]]; then
  echo "Не найден ${CONF} — похоже, OpenVPN на этом сервере не установлен этим проектом." >&2
  exit 1
fi

if [[ ! -f "${SCRIPT_DIR}/templates/check-cn-username.sh" ]]; then
  echo "Не найден ${SCRIPT_DIR}/templates/check-cn-username.sh — запускайте" >&2
  echo "скрипт из корня проекта (там, где лежит папка templates/)." >&2
  exit 1
fi

echo "==> Копирую скрипты в /etc/openvpn/server/"
cp "${SCRIPT_DIR}/templates/check-cn-username.sh" /etc/openvpn/server/check-cn-username.sh
cp "${SCRIPT_DIR}/templates/client-connect.sh" /etc/openvpn/server/client-connect.sh
cp "${SCRIPT_DIR}/templates/client-disconnect.sh" /etc/openvpn/server/client-disconnect.sh
chmod 755 /etc/openvpn/server/check-cn-username.sh \
          /etc/openvpn/server/client-connect.sh \
          /etc/openvpn/server/client-disconnect.sh
echo "    готово."

cp "$CONF" "${CONF}.bak.$(date +%s)"

echo "==> Проверяю и, если нужно, дописываю директивы в server.conf"

# script-security 2 обязателен для ВСЕХ пользовательских скриптов ниже —
# без него OpenVPN не выполнит ни один из них, а незапустившийся
# client-connect трактуется как отказ клиенту (выглядит как AUTH_FAILED,
# хотя к логину/паролю отношения не имеет — та самая грабля).
if grep -q '^script-security ' "$CONF"; then
  echo "    script-security уже задан, не трогаю"
else
  echo "    добавляю: script-security 2"
  echo "script-security 2" >> "$CONF"
fi

if grep -q '^auth-user-pass-verify /etc/openvpn/server/check-cn-username.sh' "$CONF"; then
  echo "    auth-user-pass-verify уже есть, не трогаю"
else
  echo "    добавляю: auth-user-pass-verify (проверка CN=логин)"
  echo "auth-user-pass-verify /etc/openvpn/server/check-cn-username.sh via-env" >> "$CONF"
fi

if grep -q '^client-connect /etc/openvpn/server/client-connect.sh' "$CONF"; then
  echo "    client-connect уже есть, не трогаю"
else
  echo "    добавляю: client-connect (логирование подключений)"
  echo "client-connect /etc/openvpn/server/client-connect.sh" >> "$CONF"
fi

if grep -q '^client-disconnect /etc/openvpn/server/client-disconnect.sh' "$CONF"; then
  echo "    client-disconnect уже есть, не трогаю"
else
  echo "    добавляю: client-disconnect (логирование подключений)"
  echo "client-disconnect /etc/openvpn/server/client-disconnect.sh" >> "$CONF"
fi

if grep -q '^status-version 2' "$CONF"; then
  echo "    status-version 2 уже есть, не трогаю"
else
  echo "    добавляю: status-version 2 (иначе панель может не видеть подключённых)"
  echo "status-version 2" >> "$CONF"
fi

echo "==> Готовлю лог-файл подключений и logrotate"
mkdir -p /var/log/openvpn
touch /var/log/openvpn/connections.log
chmod 644 /var/log/openvpn/connections.log
cp "${SCRIPT_DIR}/templates/logrotate-openvpn.tpl" /etc/logrotate.d/openvpn-panel
echo "    готово."

echo "==> Перезапускаю OpenVPN (текущие сессии разорвутся)"
systemctl restart openvpn-server@server
sleep 1
if systemctl is-active --quiet openvpn-server@server; then
  echo "    служба поднялась."
else
  echo ""
  echo "!!! OpenVPN не поднялся после изменений!" >&2
  echo "    Смотрите: journalctl -u openvpn-server@server -n 80 --no-pager" >&2
  echo "    Бэкап предыдущего рабочего конфига: ${CONF}.bak.*" >&2
  echo "    Откат: sudo cp ${CONF}.bak.<таймстамп> ${CONF} && sudo systemctl restart openvpn-server@server" >&2
  exit 1
fi

echo ""
echo "======================================================================"
echo " Готово:"
echo " - Проверка «логин == CN сертификата» активна."
echo " - Логирование подключений активно (/var/log/openvpn/connections.log)."
echo ""
echo " Не забудьте обновить саму панель, если ещё не обновляли, чтобы в ней"
echo " появилась вкладка «Логирование»:"
echo "   sudo ./update-panel.sh"
echo "======================================================================"
