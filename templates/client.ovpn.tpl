client
dev tun
proto __PROTO__
remote __REMOTE_HOST__ __REMOTE_PORT__
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256

# Логин и пароль (учётка AD) запрашиваются при каждом подключении —
# клиент OpenVPN сам покажет окно ввода. Пароли в файл не зашиваем.
auth-user-pass
auth-nocache

verb 3
key-direction 1

<ca>
__CA_CERT__
</ca>
<cert>
__CLIENT_CERT__
</cert>
<key>
__CLIENT_KEY__
</key>
<tls-auth>
__TA_KEY__
</tls-auth>
