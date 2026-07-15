import os
import sqlite3
from functools import wraps

from flask import Flask, flash, redirect, session, url_for

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"), static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = "troque-esta-chave-por-uma-secreta-e-aleatoria"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
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
            status TEXT NOT NULL DEFAULT 'Aberta',
            discovered_date TEXT NOT NULL,
            resolved_date TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    """)
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

app.jinja_env.globals.update(SEVERITY_BADGE=SEVERITY_BADGE, STATUS_BADGE=STATUS_BADGE)


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
