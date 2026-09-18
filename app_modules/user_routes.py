from flask import flash, redirect, render_template, request, session, url_for

from app_modules.core import VALID_ROLES, admin_required, app, get_db
from app_modules.audit import record_audit


def register_user_routes():
    @app.route("/users")
    @admin_required
    def users():
        conn = get_db()
        all_users = conn.execute(
            "SELECT id, username, role FROM users ORDER BY username"
        ).fetchall()
        conn.close()
        return render_template("users.html", users=all_users)

    @app.route("/users/<int:user_id>/role", methods=["POST"])
    @admin_required
    def change_role(user_id):
        new_role = request.form.get("role", "")
        if new_role not in VALID_ROLES:
            flash("Perfil inválido.", "danger")
            return redirect(url_for("users"))

        if user_id == session["user_id"] and new_role != "admin":
            flash("Você não pode remover seu próprio acesso de administrador.", "warning")
            return redirect(url_for("users"))

        conn = get_db()
        user_exists = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_exists:
            conn.close()
            flash("Usuário não encontrado.", "danger")
            return redirect(url_for("users"))

        old_user = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        old_role = old_user["role"]
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()
        record_audit("USER_ROLE_CHANGED", "user", user_id, old_value=old_role, new_value=new_role)

        flash("Perfil atualizado.", "success")
        return redirect(url_for("users"))
