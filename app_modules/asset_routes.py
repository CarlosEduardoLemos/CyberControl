from datetime import datetime

from flask import flash, redirect, render_template, request, session, url_for

from app_modules.core import app, get_db, login_required, admin_required


def register_asset_routes():
    @app.route("/assets")
    @login_required
    def assets():
        conn = get_db()
        all_assets = conn.execute("""
            SELECT a.*,
                   (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = a.id) AS vuln_count
            FROM assets a
            ORDER BY a.created_at DESC
        """).fetchall()
        conn.close()
        return render_template("assets.html", assets=all_assets)

    @app.route("/assets/add", methods=["GET", "POST"])
    @login_required
    def add_asset():
        if request.method == "POST":
            name = request.form["name"].strip()
            ip_address = request.form.get("ip_address", "").strip()
            asset_type = request.form.get("asset_type", "Servidor")
            owner = request.form.get("owner", "").strip()

            if not name:
                flash("O nome do ativo é obrigatório.", "danger")
                return redirect(url_for("add_asset"))

            conn = get_db()
            conn.execute("""
                INSERT INTO assets (name, ip_address, asset_type, owner, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, ip_address, asset_type, owner, session["user_id"], datetime.now().isoformat()))
            conn.commit()
            conn.close()

            flash("Ativo cadastrado com sucesso.", "success")
            return redirect(url_for("assets"))

        return render_template("add_asset.html")

    @app.route("/assets/<int:asset_id>")
    @login_required
    def asset_detail(asset_id):
        conn = get_db()
        asset = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            conn.close()
            flash("Ativo não encontrado.", "danger")
            return redirect(url_for("assets"))

        vulns = conn.execute("""
            SELECT * FROM vulnerabilities WHERE asset_id = ? ORDER BY cvss_score DESC
        """, (asset_id,)).fetchall()
        conn.close()

        return render_template("asset_detail.html", asset=asset, vulns=vulns)

    @app.route("/assets/<int:asset_id>/delete", methods=["POST"])
    @admin_required
    def delete_asset(asset_id):
        conn = get_db()
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        conn.close()
        flash("Ativo removido.", "info")
        return redirect(url_for("assets"))
