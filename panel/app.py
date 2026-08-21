import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session, render_template,
    flash, Response, abort, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

EASYRSA_DIR = os.environ.get("EASYRSA_DIR", "/etc/openvpn/easy-rsa")
SERVER_CN = os.environ.get("SERVER_CN", "vpn-server")
TA_KEY_PATH = os.environ.get("TA_KEY_PATH", "/etc/openvpn/server/ta.key")
SERVER_CONF_PATH = os.environ.get("SERVER_CONF_PATH", "/etc/openvpn/server/server.conf")
PAM_RADIUS_CONF_PATH = os.environ.get("PAM_RADIUS_CONF_PATH", "/etc/pam_radius_auth.conf")
CCD_DIR = os.environ.get("CCD_DIR", "/etc/openvpn/server/ccd")
OPENVPN_STATUS_PATH = os.environ.get("OPENVPN_STATUS_PATH", "/etc/openvpn/server/openvpn-status.log")
CONNECTIONS_LOG_PATH = os.environ.get("CONNECTIONS_LOG_PATH", "/var/log/openvpn/connections.log")
OPENVPN_APP_LOG_PATH = os.environ.get("OPENVPN_APP_LOG_PATH", "/var/log/openvpn/server.log")
MGMT_HOST = os.environ.get("MGMT_HOST", "127.0.0.1")
MGMT_PORT = int(os.environ.get("MGMT_PORT", "7505"))
PANEL_PORT = os.environ.get("PANEL_PORT", "8080")
NET_IFACE = os.environ.get("NET_IFACE", "eth0")
DB_PATH = os.environ.get("PANEL_DB", os.path.join(BASE_DIR, "instance", "panel.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

CN_RE = re.compile(r"^[A-Za-z0-9._-]+$")
ADMIN_USER_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


# --------------------------------------------------------------------------
# DB helpers
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_setting(key, default=""):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()
    conn.close()


def log_action(action, details=""):
    """Пишет запись в журнал действий. actor берётся из текущей сессии."""
    actor = session.get("admin", "system")
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, details) VALUES (?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor, action, details),
    )
    conn.commit()
    conn.close()


def get_recent_actions(limit=25):
    conn = get_db()
    rows = conn.execute(
        "SELECT ts, actor, action, details FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return rows


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        row = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session["admin"] = username
            log_action("login", "")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Неверный логин или пароль", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if session.get("admin"):
        log_action("logout", "")
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# easy-rsa helpers
# --------------------------------------------------------------------------
def read_client_index():
    """Парсит pki/index.txt easy-rsa, возвращает список клиентов (без сервера)."""
    index_path = os.path.join(EASYRSA_DIR, "pki", "index.txt")
    clients = []
    if not os.path.exists(index_path):
        return clients
    with open(index_path) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) < 6:
                continue
            status, exp_date, rev_date, serial, filename, subject = parts[:6]
            m = re.search(r"/CN=([^/]+)", subject)
            if not m:
                continue
            cn = m.group(1)
            if cn == SERVER_CN:
                continue
            clients.append({
                "cn": cn,
                "status": "valid" if status == "V" else "revoked",
                "expires": exp_date,
            })
    return clients


def run_script(script_name, *args, env_extra=None):
    path = os.path.join(SCRIPTS_DIR, script_name)
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    is_root = os.geteuid() == 0
    cmd = [path, *args] if is_root else ["/usr/bin/sudo", "-n", path, *args]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return result


def read_status_log():
    """Парсит openvpn-status.log. Поддерживает оба формата:
    - version 2 (машиночитаемый CSV, "HEADER,CLIENT_LIST,..." + "CLIENT_LIST,...") —
      основной ожидаемый формат, задаётся директивой status-version 2.
    - version 1 (текстовый, "OpenVPN CLIENT LIST" + "ROUTING TABLE") — фолбэк
      на случай нестандартной конфигурации.
    Возвращает {cn: {"real_addr": ..., "vpn_addr": ...}}.
    """
    if not os.path.exists(OPENVPN_STATUS_PATH):
        return {}

    with open(OPENVPN_STATUS_PATH) as f:
        raw = f.read()

    if "CLIENT_LIST" in raw:
        return _parse_status_v2(raw)
    return _parse_status_v1(raw)


def _parse_status_v2(raw):
    connected = {}
    client_cols = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("HEADER,CLIENT_LIST,"):
            client_cols = line.split(",")[2:]  # имена колонок по порядку
            continue
        if line.startswith("CLIENT_LIST,") and client_cols:
            values = line.split(",")[1:]
            row = dict(zip(client_cols, values))
            cn = row.get("Common Name", "")
            if not cn:
                continue
            real_addr_full = row.get("Real Address", "")
            real_addr = real_addr_full.rsplit(":", 1)[0] if ":" in real_addr_full else real_addr_full
            vpn_addr = row.get("Virtual Address", "")
            connected[cn] = {
                "real_addr": real_addr,
                "vpn_addr": vpn_addr,
                "bytes_received": row.get("Bytes Received", ""),
                "bytes_sent": row.get("Bytes Sent", ""),
            }
    return connected


def _parse_status_v1(raw):
    connected = {}
    routing = {}  # cn -> virtual address, из секции ROUTING TABLE
    section = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("OpenVPN CLIENT LIST"):
            section = "list"
            continue
        if line.startswith("ROUTING TABLE"):
            section = "routing"
            continue
        if line.startswith("GLOBAL STATS"):
            section = None
            continue
        if not line:
            continue
        if section == "list" and not line.startswith("Common Name") and not line.startswith("Updated"):
            parts = line.split(",")
            if len(parts) >= 5:
                cn = parts[0]
                real_addr_full = parts[1]
                real_addr = real_addr_full.rsplit(":", 1)[0] if ":" in real_addr_full else real_addr_full
                connected[cn] = {"real_addr": real_addr, "vpn_addr": ""}
        elif section == "routing" and not line.startswith("Virtual Address"):
            parts = line.split(",")
            if len(parts) >= 2:
                vpn_addr, cn = parts[0], parts[1]
                routing[cn] = vpn_addr

    for cn, vpn_addr in routing.items():
        if cn in connected:
            connected[cn]["vpn_addr"] = vpn_addr
    return connected


def mgmt_kill(cn):
    """Посылает команду kill <cn> на management-интерфейс OpenVPN,
    чтобы сразу разорвать активную сессию отозванного пользователя."""
    try:
        with socket.create_connection((MGMT_HOST, MGMT_PORT), timeout=3) as s:
            s.recv(4096)  # приветствие
            s.sendall(f"kill {cn}\n".encode())
            s.recv(4096)
            s.sendall(b"quit\n")
    except OSError:
        pass


def mgmt_status_v2(timeout=3):
    """Запрашивает живой статус через management-интерфейс (команда
    'status 2') — тот же формат, что и файл status-log version 2, но без
    зависимости от периодичности его записи на диск: данные актуальны на
    момент запроса. Возвращает сырой текст ответа, либо None при ошибке
    соединения (например, OpenVPN сейчас не поднят)."""
    try:
        with socket.create_connection((MGMT_HOST, MGMT_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            buf = b""
            try:
                buf += s.recv(4096)  # приветствие, можно игнорировать
            except socket.timeout:
                pass
            s.sendall(b"status 2\n")
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                if b"\nEND" in buf:
                    break
            try:
                s.sendall(b"quit\n")
            except OSError:
                pass
            return buf.decode("utf-8", errors="replace")
    except OSError:
        return None


# --------------------------------------------------------------------------
# Логирование: подключения пользователей + сырой лог OpenVPN
# --------------------------------------------------------------------------
def read_connection_log(limit=300, cn_filter=""):
    """Читает JSON-lines лог подключений/отключений (пишут client-connect.sh
    и client-disconnect.sh), возвращает последние limit записей, новые
    сверху. Битые строки (например, лог обрезался ровно посередине записи
    при ротации) молча пропускаются."""
    if not os.path.exists(CONNECTIONS_LOG_PATH):
        return []
    entries = []
    with open(CONNECTIONS_LOG_PATH) as f:
        lines = f.readlines()
    cn_filter_lower = cn_filter.lower().strip()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if cn_filter_lower and cn_filter_lower not in entry.get("cn", "").lower():
            continue
        entries.append(entry)
    entries.reverse()
    return entries[:limit]


def tail_text_file(path, limit=300):
    """Возвращает последние limit строк текстового файла как список (без
    завершающих переносов), либо пустой список, если файла нет."""
    if not os.path.exists(path):
        return []
    with open(path, errors="replace") as f:
        lines = f.readlines()
    return [line.rstrip("\n") for line in lines[-limit:]]


def format_duration(seconds):
    if seconds is None:
        return "—"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}ч {m}м"
    if m:
        return f"{m}м {s}с"
    return f"{s}с"


def format_bytes(n):
    if n is None:
        return "—"
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


# --------------------------------------------------------------------------
# Сеть: пул адресов, статические резервы
# --------------------------------------------------------------------------
def read_server_conf_summary():
    summary = {
        "subnet": "", "mask": "", "route_net": "", "route_mask": "",
        "dns": [], "pool_start": "", "pool_end": "",
        "domain": "", "extra_routes": [],
        "vpn_port": "", "vpn_proto": "",
    }
    if not os.path.exists(SERVER_CONF_PATH):
        return summary
    with open(SERVER_CONF_PATH) as f:
        content = f.read()

    first_route_seen = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("port "):
            summary["vpn_port"] = line.split()[1] if len(line.split()) > 1 else ""
        elif line.startswith("proto "):
            summary["vpn_proto"] = line.split()[1] if len(line.split()) > 1 else ""
        elif line.startswith("server "):
            parts = line.split()
            if len(parts) >= 3:
                summary["subnet"], summary["mask"] = parts[1], parts[2]
        elif line.startswith("ifconfig-pool "):
            parts = line.split()
            if len(parts) >= 3:
                summary["pool_start"], summary["pool_end"] = parts[1], parts[2]
        elif line.startswith('push "route '):
            m = re.search(r'push "route ([\d.]+) ([\d.]+)"', line)
            if m:
                if not first_route_seen:
                    # первая встреченная route-директива — основной split-route
                    summary["route_net"], summary["route_mask"] = m.group(1), m.group(2)
                    first_route_seen = True
                else:
                    # остальные — дополнительные маршруты (из EXTRA_CONFIG блока)
                    try:
                        net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
                        summary["extra_routes"].append(str(net))
                    except ValueError:
                        pass
        elif line.startswith('push "dhcp-option DNS'):
            m = re.search(r'push "dhcp-option DNS ([\d.]+)"', line)
            if m:
                summary["dns"].append(m.group(1))
        elif line.startswith('push "dhcp-option DOMAIN'):
            m = re.search(r'push "dhcp-option DOMAIN (\S+)"', line)
            if m:
                summary["domain"] = m.group(1)
    return summary


def get_network_context():
    s = read_server_conf_summary()
    try:
        network = ipaddress.ip_network(f"{s['subnet']}/{s['mask']}", strict=False)
        pool_start = ipaddress.ip_address(s["pool_start"])
        pool_end = ipaddress.ip_address(s["pool_end"])
        gateway = list(network.hosts())[0]
    except (ValueError, KeyError, IndexError):
        return None
    return {
        "network": network, "pool_start": pool_start, "pool_end": pool_end,
        "gateway": gateway, "mask": s["mask"],
    }


def list_static_assignments():
    result = {}
    if not os.path.isdir(CCD_DIR):
        return result
    for fname in os.listdir(CCD_DIR):
        path = os.path.join(CCD_DIR, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path) as f:
                content = f.read()
            m = re.search(r"ifconfig-push\s+([\d.]+)\s+", content)
            if m:
                result[fname] = m.group(1)
        except OSError:
            continue
    return result


def validate_static_ip(cn, ip_str):
    ctx = get_network_context()
    if ctx is None:
        return False, "Не удалось прочитать текущую сетевую конфигурацию сервера"

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"'{ip_str}' не похож на корректный IPv4-адрес"

    if ip not in ctx["network"]:
        return False, f"Адрес {ip} не входит в подсеть {ctx['network']}"

    if ip == ctx["gateway"]:
        return False, f"Адрес {ip} зарезервирован за самим сервером"

    if ip == ctx["network"].broadcast_address or ip == ctx["network"].network_address:
        return False, f"Адрес {ip} — адрес сети или широковещательный, использовать нельзя"

    if ctx["pool_start"] <= ip <= ctx["pool_end"]:
        return False, (
            f"Адрес {ip} входит в динамический пул ({ctx['pool_start']}-{ctx['pool_end']}) — "
            f"его может получить любой другой клиент. Выберите адрес вне этого диапазона."
        )

    existing = list_static_assignments()
    for other_cn, other_ip in existing.items():
        if other_ip == str(ip) and other_cn != cn:
            return False, f"Адрес {ip} уже закреплён за пользователем {other_cn}"

    return True, None


# --------------------------------------------------------------------------
# Нагрузка на сетевой интерфейс
# --------------------------------------------------------------------------
_net_state_lock = threading.Lock()
_net_state = {}  # iface -> {"ts": float, "rx": int, "tx": int}


def read_iface_bytes(iface):
    base = f"/sys/class/net/{iface}/statistics"
    with open(os.path.join(base, "rx_bytes")) as f:
        rx = int(f.read().strip())
    with open(os.path.join(base, "tx_bytes")) as f:
        tx = int(f.read().strip())
    return rx, tx


@app.route("/api/net-stats")
@login_required
def api_net_stats():
    iface = NET_IFACE
    try:
        rx, tx = read_iface_bytes(iface)
    except OSError:
        return jsonify({"error": f"интерфейс {iface} не найден"}), 404

    now = time.time()
    with _net_state_lock:
        prev = _net_state.get(iface)
        _net_state[iface] = {"ts": now, "rx": rx, "tx": tx}

    if prev is None or now <= prev["ts"]:
        rx_bps = tx_bps = 0.0
    else:
        dt = now - prev["ts"]
        rx_bps = max(0.0, (rx - prev["rx"]) / dt)
        tx_bps = max(0.0, (tx - prev["tx"]) / dt)

    return jsonify({"iface": iface, "rx_bps": rx_bps, "tx_bps": tx_bps})


# --------------------------------------------------------------------------
# Трафик по пользователям в реальном времени
# --------------------------------------------------------------------------
_user_traffic_lock = threading.Lock()
_user_traffic_state = {}  # cn -> {"ts": float, "rx": int, "tx": int}


@app.route("/api/user-traffic")
@login_required
def api_user_traffic():
    raw = mgmt_status_v2()
    if raw is None:
        return jsonify({"error": "management-интерфейс OpenVPN недоступен"}), 503

    connected = _parse_status_v2(raw)
    now = time.time()
    result = {}

    with _user_traffic_lock:
        for cn, info in connected.items():
            try:
                rx = int(info.get("bytes_received") or 0)
            except (TypeError, ValueError):
                rx = 0
            try:
                tx = int(info.get("bytes_sent") or 0)
            except (TypeError, ValueError):
                tx = 0

            prev = _user_traffic_state.get(cn)
            _user_traffic_state[cn] = {"ts": now, "rx": rx, "tx": tx}

            # Счётчики сбрасываются в 0 при каждом новом подключении (это не
            # общий трафик за всё время, а трафик текущей сессии) — если
            # видим "откат назад", значит это новая сессия под тем же CN,
            # а не отрицательная скорость.
            if prev is None or now <= prev["ts"] or rx < prev["rx"] or tx < prev["tx"]:
                rx_bps = tx_bps = 0.0
            else:
                dt = now - prev["ts"]
                rx_bps = max(0.0, (rx - prev["rx"]) / dt)
                tx_bps = max(0.0, (tx - prev["tx"]) / dt)

            result[cn] = {"rx_bps": rx_bps, "tx_bps": tx_bps, "rx_total": rx, "tx_total": tx}

        # чистим состояние для тех, кто уже отключился — не течём памятью
        # на сервере с большой текучкой подключений
        for stale_cn in set(_user_traffic_state.keys()) - set(connected.keys()):
            del _user_traffic_state[stale_cn]

    return jsonify(result)


# --------------------------------------------------------------------------
# Routes: dashboard
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    clients = read_client_index()
    connected = read_status_log()
    valid_count = sum(1 for c in clients if c["status"] == "valid")
    static_count = len(list_static_assignments())
    return render_template(
        "dashboard.html",
        total=len(clients),
        valid_count=valid_count,
        connected=connected,
        connected_count=len(connected),
        static_count=static_count,
        net_iface=NET_IFACE,
        recent_actions=get_recent_actions(10),
    )


# --------------------------------------------------------------------------
# Routes: users
# --------------------------------------------------------------------------
@app.route("/users")
@login_required
def users():
    clients = read_client_index()
    connected = read_status_log()
    static_ips = list_static_assignments()
    for c in clients:
        conn_info = connected.get(c["cn"])
        c["online"] = conn_info is not None
        c["public_ip"] = conn_info["real_addr"] if conn_info else ""
        c["vpn_ip_now"] = conn_info["vpn_addr"] if conn_info else ""
        c["static_ip"] = static_ips.get(c["cn"], "")
    return render_template("users.html", clients=clients)


@app.route("/users/new", methods=["POST"])
@login_required
def users_new():
    cn = request.form.get("cn", "").strip()
    static_ip = request.form.get("static_ip", "").strip()

    if not cn or not CN_RE.match(cn):
        flash("Недопустимое имя пользователя. Разрешены буквы, цифры, точка, дефис, подчёркивание.", "error")
        return redirect(url_for("users"))

    existing = {c["cn"] for c in read_client_index()}
    if cn in existing:
        flash(f"Пользователь {cn} уже существует", "error")
        return redirect(url_for("users"))

    if static_ip:
        ok, err = validate_static_ip(cn, static_ip)
        if not ok:
            flash(err, "error")
            return redirect(url_for("users"))

    result = run_script("issue-client.sh", cn)
    if result.returncode != 0:
        flash(f"Ошибка выпуска сертификата: {result.stderr[-800:]}", "error")
        return redirect(url_for("users"))

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO clients (cn, created_at, note, static_ip) VALUES (?, ?, ?, ?)",
        (cn, datetime.now(timezone.utc).isoformat(), "", static_ip or None),
    )
    conn.commit()
    conn.close()

    if static_ip:
        ctx = get_network_context()
        mask = ctx["mask"] if ctx else "255.255.255.0"
        static_result = run_script("set-static-ip.sh", cn, static_ip, mask)
        if static_result.returncode != 0:
            flash(f"Пользователь создан, но не удалось закрепить IP: {static_result.stderr[-500:]}", "error")
            return redirect(url_for("users"))

    log_action("user_create", f"cn={cn} static_ip={static_ip or '-'}")
    flash(f"Пользователь {cn} создан. Не забудьте скачать .ovpn.", "success")
    return redirect(url_for("users"))


@app.route("/users/<cn>/revoke", methods=["POST"])
@login_required
def users_revoke(cn):
    if not CN_RE.match(cn):
        abort(400)
    result = run_script("revoke-client.sh", cn)
    if result.returncode != 0:
        flash(f"Ошибка отзыва: {result.stderr[-800:]}", "error")
        return redirect(url_for("users"))
    mgmt_kill(cn)
    run_script("unset-static-ip.sh", cn)
    log_action("user_revoke", f"cn={cn}")
    flash(f"Пользователь {cn} отозван и отключён.", "success")
    return redirect(url_for("users"))


@app.route("/users/<cn>/static", methods=["POST"])
@login_required
def users_set_static(cn):
    if not CN_RE.match(cn):
        abort(400)
    ip_str = request.form.get("static_ip", "").strip()
    if not ip_str:
        flash("Введите IP-адрес", "error")
        return redirect(url_for("users"))

    ok, err = validate_static_ip(cn, ip_str)
    if not ok:
        flash(err, "error")
        return redirect(url_for("users"))

    ctx = get_network_context()
    mask = ctx["mask"] if ctx else "255.255.255.0"
    result = run_script("set-static-ip.sh", cn, ip_str, mask)
    if result.returncode != 0:
        flash(f"Ошибка назначения адреса: {result.stderr[-500:]}", "error")
        return redirect(url_for("users"))

    conn = get_db()
    conn.execute("UPDATE clients SET static_ip = ? WHERE cn = ?", (ip_str, cn))
    conn.commit()
    conn.close()

    log_action("static_ip_set", f"cn={cn} ip={ip_str}")
    flash(f"За пользователем {cn} закреплён адрес {ip_str}. Применится при следующем подключении.", "success")
    return redirect(url_for("users"))


@app.route("/users/<cn>/static/remove", methods=["POST"])
@login_required
def users_remove_static(cn):
    if not CN_RE.match(cn):
        abort(400)
    result = run_script("unset-static-ip.sh", cn)
    if result.returncode != 0:
        flash(f"Ошибка снятия адреса: {result.stderr[-500:]}", "error")
        return redirect(url_for("users"))

    conn = get_db()
    conn.execute("UPDATE clients SET static_ip = NULL WHERE cn = ?", (cn,))
    conn.commit()
    conn.close()

    log_action("static_ip_remove", f"cn={cn}")
    flash(f"Статический адрес снят с пользователя {cn}.", "success")
    return redirect(url_for("users"))


@app.route("/users/<cn>/download")
@login_required
def users_download(cn):
    if not CN_RE.match(cn):
        abort(400)

    ca_path = os.path.join(EASYRSA_DIR, "pki", "ca.crt")
    cert_path = os.path.join(EASYRSA_DIR, "pki", "issued", f"{cn}.crt")
    key_path = os.path.join(EASYRSA_DIR, "pki", "private", f"{cn}.key")

    for p in (ca_path, cert_path, key_path, TA_KEY_PATH):
        if not os.path.exists(p):
            abort(404, f"Не найден файл: {p}")

    def read(p):
        with open(p) as f:
            return f.read().strip()

    tpl_path = os.path.join(BASE_DIR, "client.ovpn.tpl")
    with open(tpl_path) as f:
        tpl = f.read()

    ovpn = (
        tpl
        .replace("__PROTO__", get_setting("proto", "udp"))
        .replace("__REMOTE_HOST__", get_setting("remote_host", ""))
        .replace("__REMOTE_PORT__", get_setting("remote_port", "1194"))
        .replace("__CA_CERT__", read(ca_path))
        .replace("__CLIENT_CERT__", extract_cert_block(read(cert_path)))
        .replace("__CLIENT_KEY__", read(key_path))
        .replace("__TA_KEY__", read(TA_KEY_PATH))
    )

    log_action("ovpn_download", f"cn={cn}")
    return Response(
        ovpn,
        mimetype="application/x-openvpn-profile",
        headers={"Content-Disposition": f"attachment; filename={cn}.ovpn"},
    )


def extract_cert_block(crt_text):
    m = re.search(r"-----BEGIN CERTIFICATE-----.*-----END CERTIFICATE-----", crt_text, re.S)
    return m.group(0) if m else crt_text


# --------------------------------------------------------------------------
# Routes: logs
# --------------------------------------------------------------------------
@app.route("/logs")
@login_required
def logs():
    cn_filter = request.args.get("cn", "").strip()

    raw_connections = read_connection_log(limit=300, cn_filter=cn_filter)
    connections = []
    for e in raw_connections:
        connections.append({
            "ts": e.get("ts", ""),
            "event": e.get("event", ""),
            "cn": e.get("cn", ""),
            "real_addr": e.get("real_addr", ""),
            "vpn_addr": e.get("vpn_addr", ""),
            "duration": format_duration(e.get("duration_sec")),
            "traffic": (
                f"↓{format_bytes(e.get('bytes_received'))} / ↑{format_bytes(e.get('bytes_sent'))}"
                if e.get("event") == "disconnect" else ""
            ),
        })

    server_log_lines = tail_text_file(OPENVPN_APP_LOG_PATH, limit=300)

    return render_template(
        "logs.html",
        connections=connections,
        server_log_lines=server_log_lines,
        cn_filter=cn_filter,
        connections_log_exists=os.path.exists(CONNECTIONS_LOG_PATH),
        server_log_exists=os.path.exists(OPENVPN_APP_LOG_PATH),
    )


# --------------------------------------------------------------------------
# Routes: settings
# --------------------------------------------------------------------------
@app.route("/settings")
@login_required
def settings():
    return render_template(
        "settings.html",
        remote_host=get_setting("remote_host", ""),
        remote_port=get_setting("remote_port", "1194"),
        proto=get_setting("proto", "udp"),
        server_conf=read_server_conf_summary(),
        panel_allowed_cidr=get_setting("panel_allowed_cidr", "10.0.0.0/8"),
        panel_port=PANEL_PORT,
        nps_host=get_setting("nps_host", ""),
        nps_port=get_setting("nps_port", "1812"),
        nps_secret=get_setting("nps_secret", ""),
        nps_timeout=get_setting("nps_timeout", "5"),
    )


@app.route("/settings/remote", methods=["POST"])
@login_required
def settings_remote():
    set_setting("remote_host", request.form.get("remote_host", "").strip())
    set_setting("remote_port", request.form.get("remote_port", "1194").strip())
    set_setting("proto", request.form.get("proto", "udp").strip())
    log_action("settings_remote", "")
    flash("Настройки сохранены. Новые .ovpn будут использовать эти значения.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/network", methods=["POST"])
@login_required
def settings_network():
    subnet = request.form.get("subnet", "").strip()
    mask = request.form.get("mask", "").strip()
    pool_start = request.form.get("pool_start", "").strip()
    pool_end = request.form.get("pool_end", "").strip()
    domain_name = request.form.get("domain_name", "").strip()
    extra_routes_raw = request.form.get("extra_routes", "").strip()
    vpn_port = request.form.get("vpn_port", "").strip()
    vpn_proto = request.form.get("vpn_proto", "udp").strip()

    try:
        network = ipaddress.ip_network(f"{subnet}/{mask}", strict=False)
        ps, pe = ipaddress.ip_address(pool_start), ipaddress.ip_address(pool_end)
        if ps not in network or pe not in network or ps > pe:
            flash("Динамический диапазон должен лежать внутри указанной подсети и start <= end", "error")
            return redirect(url_for("settings"))
    except ValueError:
        flash("Некорректные значения подсети/маски/диапазона", "error")
        return redirect(url_for("settings"))

    if not vpn_port.isdigit() or not (1 <= int(vpn_port) <= 65535):
        flash("Порт OpenVPN должен быть числом от 1 до 65535", "error")
        return redirect(url_for("settings"))
    if vpn_proto not in ("udp", "tcp"):
        flash("Протокол должен быть udp или tcp", "error")
        return redirect(url_for("settings"))

    extra_routes_cidrs = extra_routes_raw.split()
    for cidr in extra_routes_cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            flash(f"'{cidr}' в дополнительных маршрутах не похож на корректный CIDR", "error")
            return redirect(url_for("settings"))

    env_extra = {
        "VPN_PORT": vpn_port,
        "VPN_PROTO": vpn_proto,
        "VPN_SUBNET": subnet,
        "VPN_SUBNET_MASK": mask,
        "SPLIT_ROUTE_NETWORK": request.form.get("route_net", "").strip(),
        "SPLIT_ROUTE_MASK": request.form.get("route_mask", "").strip(),
        "DNS1": request.form.get("dns1", "").strip(),
        "DNS2": request.form.get("dns2", "").strip(),
        "POOL_START": pool_start,
        "POOL_END": pool_end,
        "DOMAIN_NAME": domain_name,
        "EXTRA_SPLIT_ROUTES": " ".join(extra_routes_cidrs),
    }
    if not all([env_extra["VPN_SUBNET"], env_extra["VPN_SUBNET_MASK"], env_extra["SPLIT_ROUTE_NETWORK"],
                env_extra["SPLIT_ROUTE_MASK"], env_extra["DNS1"], env_extra["DNS2"],
                env_extra["POOL_START"], env_extra["POOL_END"]]):
        flash("Все обязательные сетевые поля должны быть заполнены (домен и доп. маршруты — необязательны)", "error")
        return redirect(url_for("settings"))

    result = run_script("apply-network.sh", env_extra=env_extra)
    if result.returncode != 0:
        flash(f"Ошибка применения настроек: {result.stderr[-800:]}", "error")
    else:
        log_action("settings_network", f"{vpn_port}/{vpn_proto} {subnet}/{mask} pool {pool_start}-{pool_end} domain={domain_name or '-'}")
        flash(
            "Сетевые настройки применены, OpenVPN перезапущен (текущие сессии разорваны). "
            "Проверьте, что статические адреса пользователей всё ещё вне динамического диапазона.",
            "success",
        )
    return redirect(url_for("settings"))


@app.route("/settings/radius", methods=["POST"])
@login_required
def settings_radius():
    nps_host = request.form.get("nps_host", "").strip()
    nps_port = request.form.get("nps_port", "1812").strip()
    nps_secret = request.form.get("nps_secret", "").strip()
    nps_timeout = request.form.get("nps_timeout", "5").strip()

    if not nps_host or not nps_secret:
        flash("Адрес NPS и shared secret обязательны", "error")
        return redirect(url_for("settings"))

    result = run_script("apply-radius.sh", env_extra={
        "NPS_HOST": nps_host, "NPS_PORT": nps_port,
        "NPS_SECRET": nps_secret, "NPS_TIMEOUT": nps_timeout,
    })
    if result.returncode != 0:
        flash(f"Ошибка применения настроек RADIUS: {result.stderr[-800:]}", "error")
        return redirect(url_for("settings"))

    set_setting("nps_host", nps_host)
    set_setting("nps_port", nps_port)
    set_setting("nps_secret", nps_secret)
    set_setting("nps_timeout", nps_timeout)

    log_action("settings_radius", f"host={nps_host}:{nps_port}")
    flash("Настройки RADIUS сохранены, OpenVPN перезапущен (текущие сессии разорваны).", "success")
    return redirect(url_for("settings"))


@app.route("/settings/access", methods=["POST"])
@login_required
def settings_access():
    raw = request.form.get("panel_allowed_cidr", "").strip()
    cidrs = raw.split()
    if not cidrs:
        flash("Укажите хотя бы одну сеть", "error")
        return redirect(url_for("settings"))

    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            flash(f"'{cidr}' не похож на корректный CIDR (пример: 10.0.0.0/8)", "error")
            return redirect(url_for("settings"))

    result = run_script("apply-panel-acl.sh", env_extra={
        "PANEL_PORT": PANEL_PORT, "ALLOWED_CIDR": " ".join(cidrs),
    })
    if result.returncode != 0:
        flash(f"Ошибка применения правила доступа: {result.stderr[-800:]}", "error")
        return redirect(url_for("settings"))

    set_setting("panel_allowed_cidr", " ".join(cidrs))
    log_action("settings_access", " ".join(cidrs))
    flash(
        f"Доступ к панели теперь разрешён только с: {', '.join(cidrs)}. VPN-сессии не затронуты. "
        "Если вы зашли не из этих сетей — следующий запрос может не пройти.",
        "success",
    )
    return redirect(url_for("settings"))


# --------------------------------------------------------------------------
# Routes: admins
# --------------------------------------------------------------------------
@app.route("/admins")
@login_required
def admins():
    conn = get_db()
    rows = conn.execute("SELECT id, username, created_at FROM admins ORDER BY id").fetchall()
    conn.close()
    return render_template(
        "admins.html",
        admins=rows,
        current_admin=session.get("admin"),
        recent_actions=get_recent_actions(40),
    )


@app.route("/admins/new", methods=["POST"])
@login_required
def admins_new():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not ADMIN_USER_RE.match(username):
        flash("Логин: 3-64 символа, латиница/цифры/точка/дефис/подчёркивание", "error")
        return redirect(url_for("admins"))
    if len(password) < 8:
        flash("Пароль должен быть не короче 8 символов", "error")
        return redirect(url_for("admins"))

    conn = get_db()
    existing = conn.execute("SELECT 1 FROM admins WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        flash(f"Админ {username} уже существует", "error")
        return redirect(url_for("admins"))

    conn.execute(
        "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    log_action("admin_create", f"username={username}")
    flash(f"Админ {username} создан.", "success")
    return redirect(url_for("admins"))


@app.route("/admins/<int:admin_id>/delete", methods=["POST"])
@login_required
def admins_delete(admin_id):
    conn = get_db()
    target = conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
    if not target:
        conn.close()
        abort(404)

    if target["username"] == session.get("admin"):
        conn.close()
        flash("Нельзя удалить самого себя, пока вы залогинены под этим аккаунтом.", "error")
        return redirect(url_for("admins"))

    total = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
    if total <= 1:
        conn.close()
        flash("Нельзя удалить последнего администратора.", "error")
        return redirect(url_for("admins"))

    conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    conn.commit()
    conn.close()

    log_action("admin_delete", f"username={target['username']}")
    flash(f"Админ {target['username']} удалён.", "success")
    return redirect(url_for("admins"))


@app.route("/admins/password", methods=["POST"])
@login_required
def admins_change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")

    if len(new_password) < 8:
        flash("Новый пароль должен быть не короче 8 символов", "error")
        return redirect(url_for("admins"))

    conn = get_db()
    row = conn.execute("SELECT * FROM admins WHERE username = ?", (session["admin"],)).fetchone()
    if not row or not check_password_hash(row["password_hash"], current_password):
        conn.close()
        flash("Текущий пароль указан неверно", "error")
        return redirect(url_for("admins"))

    conn.execute(
        "UPDATE admins SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), row["id"]),
    )
    conn.commit()
    conn.close()

    log_action("admin_password_change", f"username={session['admin']}")
    flash("Пароль изменён.", "success")
    return redirect(url_for("admins"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(PANEL_PORT), debug=False)
