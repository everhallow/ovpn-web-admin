port __VPN_PORT__
proto __VPN_PROTO__
dev tun

ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/__SERVER_CN__.crt
key /etc/openvpn/easy-rsa/pki/private/__SERVER_CN__.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/server/ta.key 0
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem

topology subnet
# nopool — обязательно: директива "server" сама создаёт implicit pool на
# основе указанной подсети, и явный "ifconfig-pool" ниже конфликтует с ним
# без этого флага (OpenVPN откажется стартовать: "already defines an
# ifconfig-pool"). nopool отключает implicit pool, оставляя только наш.
server __VPN_SUBNET__ __VPN_SUBNET_MASK__ nopool
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
ifconfig-pool __POOL_START__ __POOL_END__

# Статические адреса для отдельных пользователей (файлы вида
# /etc/openvpn/server/ccd/<CN> с "ifconfig-push <ip> <mask>"),
# управляются через веб-панель.
client-config-dir /etc/openvpn/server/ccd

# Логирование подключений/отключений пользователей для веб-панели (вкладка
# "Логирование"). Пишет структурированные записи (JSON-lines) в отдельный
# файл, не смешивая с подробным логом самого OpenVPN. script-security 2
# уже включён ниже для другой проверки, отдельно повторять не нужно.
client-connect /etc/openvpn/server/client-connect.sh
client-disconnect /etc/openvpn/server/client-disconnect.sh

push "route __SPLIT_ROUTE_NETWORK__ __SPLIT_ROUTE_MASK__"
push "dhcp-option DNS __DNS1__"
push "dhcp-option DNS __DNS2__"

# --- EXTRA_CONFIG_START (управляется через веб-панель: Settings -> Сеть.
# Можно редактировать и руками между этими маркерами, панель их не тронет
# за пределами блока, но при следующем сохранении настроек сети из панели
# содержимое между маркерами будет перезаписано по данным из панели.) ---
__DOMAIN_PUSH_LINE__
__EXTRA_ROUTES_BLOCK__
# --- EXTRA_CONFIG_END ---

# Не отправляем клиенту default gateway — это split tunnel, весь остальной
# трафик клиента идёт мимо VPN, только SPLIT_ROUTE_NETWORK маршрутизируется сюда.

keepalive 10 120
cipher AES-256-GCM
auth SHA256
persist-key
persist-tun

verify-client-cert require

# Доп. проверка сверх самого RADIUS: введённый логин обязан совпадать с CN
# клиентского сертификата (регистронезависимо). Работает независимо от
# auth-блока ниже — оба хука (этот скрипт и RADIUS-плагин) должны
# подтвердить подключение, иначе OpenVPN его отклонит.
script-security 2
auth-user-pass-verify /etc/openvpn/server/check-cn-username.sh via-env

# ==== БЛОК АУТЕНТИФИКАЦИИ (PAP) ВСТАВЛЯЕТСЯ INSTALL.SH НИЖЕ ====
__AUTH_BLOCK__

# Management-интерфейс: используется веб-панелью, чтобы разрывать сессию
# сразу после отзыва пользователя (kill по CN сертификата), доступен
# только с localhost.
management 127.0.0.1 7505

status /etc/openvpn/server/openvpn-status.log
# Явно фиксируем версию формата статус-файла (version 2, машиночитаемый
# CSV с заголовком HEADER,CLIENT_LIST,...). Важно: пакет openvpn в Ubuntu
# передаёт свой --status/--status-version через systemd-юнит
# (openvpn-server@.service), и без явного указания здесь формат мог
# определяться тем юнитом, а не этим файлом — из-за этого веб-панель
# могла не видеть подключённых клиентов (искала текстовый формат version 1).
status-version 2
log-append /var/log/openvpn/server.log
verb 3
explicit-exit-notify 1
