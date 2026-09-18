from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app_modules.core import app, get_db


def register_auth_routes():
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                flash("Preencha usuário e senha.", "danger")
                return redirect(url_for("register"))

            conn = get_db()
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()

            if existing:
                conn.close()
                flash("Esse usuário já existe.", "danger")
                return redirect(url_for("register"))

            total_users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            role = "admin" if total_users == 0 else "analista"

            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), role),
            )
            conn.commit()
            conn.close()

            message = (
                "Conta criada como Administrador (primeiro usuário do sistema). Faça login."
                if role == "admin"
                else "Conta criada com sucesso! Faça login."
            )
            flash(message, "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            conn = get_db()
            user = conn.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            conn.close()

            if user and check_password_hash(user["password_hash"], password):
                csrf_token = session.get("_csrf_token")
                session.clear()
                if csrf_token:
                    session["_csrf_token"] = csrf_token
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))

            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for("login"))

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("Você saiu da sua conta.", "info")
        return redirect(url_for("login"))
