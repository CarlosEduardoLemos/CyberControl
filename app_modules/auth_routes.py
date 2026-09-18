from datetime import datetime, timedelta

from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app_modules.audit import record_audit
from app_modules.core import app, get_db

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
LOGIN_ATTEMPT_RETENTION_DAYS = 30


def _client_ip():
    return request.remote_addr or "unknown"


def _normalized_username(username):
    return (username or "").strip().lower()


def _registration_is_open(conn):
    return conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0


def _cleanup_login_attempts(conn, now):
    cutoff = (now - timedelta(days=LOGIN_ATTEMPT_RETENTION_DAYS)).isoformat()
    conn.execute("DELETE FROM login_attempts WHERE updated_at < ?", (cutoff,))


def _is_locked(conn, ip_address, username, now):
    row = conn.execute(
        "SELECT locked_until FROM login_attempts WHERE ip_address = ? AND username = ?",
        (ip_address, username),
    ).fetchone()
    if not row or not row["locked_until"]:
        return False
    try:
        return datetime.fromisoformat(row["locked_until"]) > now
    except ValueError:
        return False


def _record_failed_login(conn, ip_address, username, now):
    row = conn.execute(
        "SELECT attempt_count FROM login_attempts WHERE ip_address = ? AND username = ?",
        (ip_address, username),
    ).fetchone()
    count = (row["attempt_count"] if row else 0) + 1
    locked_until = None
    locked = False
    if count >= MAX_LOGIN_ATTEMPTS:
        locked_until = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        count = 0
        locked = True
    conn.execute(
        """
        INSERT INTO login_attempts (ip_address, username, attempt_count, locked_until, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_address, username) DO UPDATE SET
            attempt_count = excluded.attempt_count,
            locked_until = excluded.locked_until,
            updated_at = excluded.updated_at
        """,
        (ip_address, username, count, locked_until, now.isoformat()),
    )
    conn.commit()
    return locked


def register_auth_routes():
    @app.route("/register", methods=["GET", "POST"])
    def register():
        conn = get_db()
        bootstrap_open = _registration_is_open(conn)
        if not bootstrap_open and session.get("role") != "admin":
            flash("Novas contas devem ser criadas por um administrador.", "warning")
            return redirect(url_for("login" if "user_id" not in session else "dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not username or not password:
                flash("Preencha usuário e senha.", "danger")
                return redirect(url_for("register"))
            if len(username) > 80:
                flash("O usuário deve ter no máximo 80 caracteres.", "danger")
                return redirect(url_for("register"))
            if len(password) < 8:
                flash("A senha deve ter pelo menos 8 caracteres.", "danger")
                return redirect(url_for("register"))

            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                flash("Esse usuário já existe.", "danger")
                return redirect(url_for("register"))

            role = "admin" if bootstrap_open else "analista"
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
            conn.commit()
            record_audit("USER_CREATED", "user", cursor.lastrowid, new_value=f"role={role}")
            if bootstrap_open:
                flash("Conta Administrador criada. Faça login.", "success")
                return redirect(url_for("login"))
            flash("Conta de analista criada com sucesso.", "success")
            return redirect(url_for("users"))

        return render_template("register.html", bootstrap_open=bootstrap_open)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            username_key = _normalized_username(username)
            password = request.form.get("password", "")
            ip_address = _client_ip()
            now = datetime.now()
            conn = get_db()
            _cleanup_login_attempts(conn, now)
            conn.commit()

            if _is_locked(conn, ip_address, username_key, now):
                flash("Muitas tentativas para esta conta. Tente novamente em alguns minutos.", "danger")
                return redirect(url_for("login"))

            user = conn.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                conn.execute(
                    "DELETE FROM login_attempts WHERE ip_address = ? AND username = ?",
                    (ip_address, username_key),
                )
                conn.commit()
                # Rotation at the authentication boundary prevents CSRF/session fixation reuse.
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                record_audit("LOGIN_SUCCESS", "user", user["id"])
                return redirect(url_for("dashboard"))

            locked = _record_failed_login(conn, ip_address, username_key, now)
            if locked:
                record_audit("LOGIN_LOCKOUT", "authentication", None, new_value=f"username={username_key}")
            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for("login"))

        conn = get_db()
        return render_template("login.html", registration_open=_registration_is_open(conn))

    @app.route("/logout", methods=["POST"])
    def logout():
        user_id = session.get("user_id")
        if user_id:
            record_audit("LOGOUT", "user", user_id)
        session.clear()
        flash("Você saiu da sua conta.", "info")
        return redirect(url_for("login"))
