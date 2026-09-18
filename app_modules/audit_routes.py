from flask import render_template

from app_modules.core import admin_required, app, get_db


def register_audit_routes():
    @app.route("/audit")
    @admin_required
    def audit():
        conn = get_db()
        logs = conn.execute("""
            SELECT l.*, u.username
            FROM audit_logs l
            LEFT JOIN users u ON u.id = l.user_id
            ORDER BY l.created_at DESC
            LIMIT 200
        """).fetchall()
        conn.close()
        return render_template("audit.html", logs=logs)
