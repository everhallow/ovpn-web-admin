#!/usr/bin/env bash
# Вызывается OpenVPN через client-disconnect на каждое отключение (в т.ч.
# при разрыве через kill из панели). Пишет JSON-строку с длительностью
# сессии и трафиком.
set -euo pipefail

LOG_FILE="${CONNECTIONS_LOG_PATH:-/var/log/openvpn/connections.log}"

python3 - "$LOG_FILE" << 'PY'
import json
import os
import sys
import datetime

def to_int(val):
    try:
        return int(val)
    except (TypeError, ValueError):
        return None

entry = {
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "event": "disconnect",
    "cn": os.environ.get("common_name", ""),
    "real_addr": os.environ.get("trusted_ip", ""),
    "vpn_addr": os.environ.get("ifconfig_pool_remote_ip", ""),
    "duration_sec": to_int(os.environ.get("time_duration")),
    "bytes_received": to_int(os.environ.get("bytes_received")),
    "bytes_sent": to_int(os.environ.get("bytes_sent")),
}
with open(sys.argv[1], "a") as f:
    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
PY

exit 0
