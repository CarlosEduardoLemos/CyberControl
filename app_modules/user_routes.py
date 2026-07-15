from flask import flash, redirect, render_template, request, session, url_for

from app_modules.core import app, get_db, admin_required


def register_user_routes():
    @app.route("/users")
    @admin_required
    def users():
        conn = get_db()
        all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        conn.close()
        return render_template("users.html", users=all_users)

    @app.route("/users/<int:user_id>/role", methods=["POST"])
    @admin_required
    def change_role(user_id):
        new_role = request.form["role"]
        if new_role not in ("admin", "analista"):
            flash("Perfil inválido.", "danger")
            return redirect(url_for("users"))

        if user_id == session["user_id"] and new_role != "admin":
            flash("Você não pode remover seu próprio acesso de administrador.", "warning")
            return redirect(url_for("users"))

        conn = get_db()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        conn.close()

        flash("Perfil atualizado.", "success")
        return redirect(url_for("users"))
