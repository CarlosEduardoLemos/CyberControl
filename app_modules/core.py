import hmac
import os
import secrets
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, redirect, request, session, url_for

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = os.path.join(BASE_DIR, "database.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analista'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT,
            asset_type TEXT NOT NULL DEFAULT 'Servidor',
            owner TEXT,
            criticality TEXT NOT NULL DEFAULT 'Média',
            internet_exposed INTEGER NOT NULL DEFAULT 0,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            cvss_score REAL NOT NULL DEFAULT 0,
            severity TEXT NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0,
            risk_level TEXT NOT NULL DEFAULT 'Baixo',
            status TEXT NOT NULL DEFAULT 'Aberta',
            discovered_date TEXT NOT NULL,
            resolved_date TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER,
            old_value TEXT,
            new_value TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    """)
    asset_columns = {row["name"] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
    vuln_columns = {row["name"] for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()}
    if "criticality" not in asset_columns:
        conn.execute("ALTER TABLE assets ADD COLUMN criticality TEXT NOT NULL DEFAULT 'Média'")
    if "internet_exposed" not in asset_columns:
        conn.execute("ALTER TABLE assets ADD COLUMN internet_exposed INTEGER NOT NULL DEFAULT 0")
    if "risk_score" not in vuln_columns:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN risk_score REAL NOT NULL DEFAULT 0")
    if "risk_level" not in vuln_columns:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN risk_level TEXT NOT NULL DEFAULT 'Baixo'")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset ON vulnerabilities(asset_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)")
    conn.commit()
    conn.close()


def cvss_to_severity(score):
    score = float(score)
    if score <= 0:
        return "Nenhuma"
    if score < 4:
        return "Baixa"
    if score < 7:
        return "Média"
    if score < 9:
        return "Alta"
    return "Crítica"


SEVERITY_ORDER = {"Crítica": 4, "Alta": 3, "Média": 2, "Baixa": 1, "Nenhuma": 0}
SEVERITY_BADGE = {
    "Crítica": "bg-dark",
    "Alta": "bg-danger",
    "Média": "bg-warning text-dark",
    "Baixa": "bg-info text-dark",
    "Nenhuma": "bg-secondary",
}
STATUS_BADGE = {
    "Aberta": "bg-danger",
    "Em andamento": "bg-warning text-dark",
    "Resolvida": "bg-success",
}
VALID_STATUSES = frozenset(STATUS_BADGE)
VALID_ROLES = frozenset({"admin", "analista"})

app.jinja_env.globals.update(SEVERITY_BADGE=SEVERITY_BADGE, STATUS_BADGE=STATUS_BADGE)


def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


app.jinja_env.globals["csrf_token"] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return

    expected = session.get("_csrf_token")
    supplied = request.form.get("_csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="Token CSRF inválido ou ausente.")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para continuar.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Faça login para continuar.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Apenas administradores podem acessar essa área.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)

    return decorated
