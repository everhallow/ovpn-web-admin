#!/usr/bin/env bash
# Вызывается OpenVPN через client-connect на каждое успешное подключение.
# Пишет одну JSON-строку в /var/log/openvpn/connections.log — отдельно от
# подробного лога самого OpenVPN, чтобы веб-панель могла показывать
# историю подключений пользователей в удобном виде (вкладка "Логирование").
set -euo pipefail

LOG_FILE="${CONNECTIONS_LOG_PATH:-/var/log/openvpn/connections.log}"

python3 - "$LOG_FILE" << 'PY'
import json
import os
import sys
import datetime

entry = {
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "event": "connect",
    "cn": os.environ.get("common_name", ""),
    "real_addr": os.environ.get("trusted_ip", ""),
    "vpn_addr": os.environ.get("ifconfig_pool_remote_ip", ""),
}
with open(sys.argv[1], "a") as f:
    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
PY

exit 0
