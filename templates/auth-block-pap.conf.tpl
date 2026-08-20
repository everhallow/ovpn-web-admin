# Аутентификация (PAP): обязательный клиентский сертификат (mutual TLS) +
# логин/пароль пользователя, который плагин auth-pam передаёт в PAM,
# а PAM (pam_radius_auth) проверяет через ваш Windows NPS. Пароль передаётся
# в RADIUS Access-Request как атрибут User-Password (RFC 2865, PAP).
plugin __AUTH_PAM_PLUGIN_PATH__ openvpn
