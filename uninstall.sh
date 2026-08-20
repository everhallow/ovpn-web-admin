#!/usr/bin/env bash
# =========================================================================
# uninstall.sh — полностью убирает всё, что поставил install.sh:
# OpenVPN, PKI, PAM/RADIUS-конфиг, веб-панель, связанные ufw-правила,
# NAT-правило и systemd-юниты. VM трогать не нужно.
#
# Запускать от root: sudo ./uninstall.sh
# Флаги:
#   --purge-packages   дополнительно снести apt-пакеты openvpn/easy-rsa/
#                       libpam-radius-auth (по умолчанию остаются —
#                       конфиги и так удаляются, пакеты безобидны)
#   --yes               не спрашивать подтверждения
# =========================================================================
set -euo pipefail

PURGE_PACKAGES=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --purge-packages) PURGE_PACKAGES=1 ;;
    --yes) ASSUME_YES=1 ;;
    *) echo "Неизвестный флаг: $arg" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Запускайте от root (sudo ./uninstall.sh)" >&2
  exit 1
fi

echo "Это удалит: службы openvpn-server@server и ovpn-panel, весь /etc/openvpn,"
echo "/etc/pam_radius_auth.conf, /etc/pam.d/openvpn, /opt/ovpn-panel, связанные"
echo "правила ufw (порт OpenVPN и доступ к панели) и NAT-правило (если было включено)."
echo "Правило для SSH (OpenSSH) и остальные ваши ufw-правила НЕ трогаются."
echo ""
if [[ "$ASSUME_YES" -ne 1 ]]; then
  read -r -p "Продолжить? (yes/no) " answer
  [[ "$answer" == "yes" ]] || { echo "Отменено."; exit 0; }
fi

# -------------------------------------------------------------------------
# 1. Службы
# -------------------------------------------------------------------------
echo "==> Останавливаю и отключаю службы"
systemctl disable --now ovpn-panel.service 2>/dev/null || true
systemctl disable --now openvpn-server@server.service 2>/dev/null || true
systemctl disable --now ovpn-nat.service 2>/dev/null || true

rm -f /etc/systemd/system/ovpn-panel.service
rm -f /etc/systemd/system/ovpn-nat.service
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# -------------------------------------------------------------------------
# 2. ufw: убираем только наши правила, остальное не трогаем
# -------------------------------------------------------------------------
echo "==> Убираю правила ufw, связанные с OpenVPN и панелью"
if command -v ufw >/dev/null 2>&1; then
  # правила панели (по комментарию ovpn-panel-acl)
  while true; do
    rule_num="$(ufw status numbered | grep 'ovpn-panel-acl' | head -n1 | grep -oP '^\[\s*\K[0-9]+' || true)"
    [[ -z "$rule_num" ]] && break
    ufw --force delete "$rule_num" >/dev/null
  done
  # правило порта OpenVPN (по комментарию "OpenVPN")
  while true; do
    rule_num="$(ufw status numbered | grep '(OpenVPN)' | head -n1 | grep -oP '^\[\s*\K[0-9]+' || true)"
    [[ -z "$rule_num" ]] && break
    ufw --force delete "$rule_num" >/dev/null
  done
  ufw reload
else
  echo "    ufw не установлен, пропускаю"
fi

# -------------------------------------------------------------------------
# 3. NAT-правило (если ENABLE_NAT=yes был при установке)
# -------------------------------------------------------------------------
echo "==> Убираю NAT-правило (если было)"
if [[ -f /etc/openvpn/server/nat-up.sh ]]; then
  # пытаемся вычистить конкретное правило по маске сети, которая была в нём прописана
  SUBNET_CIDR="$(grep -oP '(?<=-s )[\d./]+' /etc/openvpn/server/nat-up.sh | head -n1 || true)"
  IFACE="$(grep -oP '(?<=-o )\S+(?= -j MASQUERADE)' /etc/openvpn/server/nat-up.sh | head -n1 || true)"
  if [[ -n "$SUBNET_CIDR" && -n "$IFACE" ]]; then
    iptables -t nat -D POSTROUTING -s "$SUBNET_CIDR" -o "$IFACE" -j MASQUERADE 2>/dev/null || true
  fi
fi

# -------------------------------------------------------------------------
# 4. Конфиги и данные OpenVPN / PKI
# -------------------------------------------------------------------------
echo "==> Удаляю /etc/openvpn (сертификаты, ключи, CRL, server.conf, ccd)"
rm -rf /etc/openvpn
rm -rf /var/log/openvpn

# -------------------------------------------------------------------------
# 5. PAM / RADIUS
# -------------------------------------------------------------------------
echo "==> Удаляю конфиг pam_radius_auth"
rm -f /etc/pam_radius_auth.conf
rm -f /etc/pam.d/openvpn

# -------------------------------------------------------------------------
# 6. Веб-панель
# -------------------------------------------------------------------------
echo "==> Удаляю веб-панель /opt/ovpn-panel"
rm -rf /opt/ovpn-panel

# -------------------------------------------------------------------------
# 7. (опционально) сами пакеты
# -------------------------------------------------------------------------
if [[ "$PURGE_PACKAGES" -eq 1 ]]; then
  echo "==> Удаляю пакеты openvpn easy-rsa libpam-radius-auth"
  DEBIAN_FRONTEND=noninteractive apt-get purge -y openvpn easy-rsa libpam-radius-auth
  apt-get autoremove -y
else
  echo "==> Пакеты openvpn/easy-rsa/libpam-radius-auth оставлены как есть"
  echo "    (запустите с --purge-packages, если хотите снести и их)"
fi

echo ""
echo "======================================================================"
echo " Готово. Проверить, что ничего не осталось висеть:"
echo "   systemctl status openvpn-server@server ovpn-panel"
echo "   ip a show tun0        # интерфейса быть не должно"
echo "   ufw status            # правил OpenVPN/панели быть не должно"
echo " sysctl net.ipv4.ip_forward оставлен включённым — если хотите откатить,"
echo " уберите строку net.ipv4.ip_forward=1 из /etc/sysctl.conf вручную."
echo "======================================================================"
