import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("PANEL_DB", os.path.join(os.path.dirname(__file__), "instance", "panel.db"))
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.executescript(
    """
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS clients (
        cn TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        note TEXT,
        static_ip TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT
    );
    """
)

# миграции для БД, созданных до появления новых колонок
existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(clients)").fetchall()}
if "static_ip" not in existing_cols:
    cur.execute("ALTER TABLE clients ADD COLUMN static_ip TEXT")

admin_cols = {row[1] for row in cur.execute("PRAGMA table_info(admins)").fetchall()}
if "created_at" not in admin_cols:
    cur.execute("ALTER TABLE admins ADD COLUMN created_at TEXT")

admin_user = os.environ.get("PANEL_ADMIN_USER", "admin")
admin_pass = os.environ.get("PANEL_ADMIN_PASS", "admin")

cur.execute(
    "INSERT OR IGNORE INTO admins (username, password_hash, created_at) VALUES (?, ?, datetime('now'))",
    (admin_user, generate_password_hash(admin_pass)),
)

defaults = {
    "remote_host": os.environ.get("DEFAULT_REMOTE_HOST", ""),
    "remote_port": os.environ.get("DEFAULT_REMOTE_PORT", "1194"),
    "proto": os.environ.get("DEFAULT_PROTO", "udp"),
    "panel_allowed_cidr": os.environ.get("DEFAULT_PANEL_ALLOWED_CIDR", "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"),
    "nps_host": os.environ.get("DEFAULT_NPS_HOST", ""),
    "nps_port": os.environ.get("DEFAULT_NPS_PORT", "1812"),
    "nps_secret": os.environ.get("DEFAULT_NPS_SECRET", ""),
    "nps_timeout": os.environ.get("DEFAULT_NPS_TIMEOUT", "5"),
}
for k, v in defaults.items():
    cur.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

conn.commit()
conn.close()
print(f"DB initialized at {DB_PATH}, admin user: {admin_user}")
