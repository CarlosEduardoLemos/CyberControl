from datetime import datetime

from flask import flash, redirect, render_template, request, session, url_for

from app_modules.core import admin_required, app, get_db, login_required
from app_modules.audit import record_audit


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
            name = request.form.get("name", "").strip()
            ip_address = request.form.get("ip_address", "").strip()
            asset_type = request.form.get("asset_type", "Servidor").strip()
            owner = request.form.get("owner", "").strip()
            criticality = request.form.get("criticality", "Média").strip()
            internet_exposed = 1 if request.form.get("internet_exposed") else 0
            if criticality not in {"Baixa", "Média", "Alta", "Crítica"}:
                flash("Criticidade inválida.", "danger")
                return redirect(url_for("add_asset"))

            if not name:
                flash("O nome do ativo é obrigatório.", "danger")
                return redirect(url_for("add_asset"))

            conn = get_db()
            conn.execute("""
                INSERT INTO assets
                    (name, ip_address, asset_type, owner, criticality, internet_exposed, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, ip_address, asset_type, owner, criticality, internet_exposed, session["user_id"], datetime.now().isoformat()))
            conn.commit()
            asset_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            conn.close()
            record_audit("ASSET_CREATED", "asset", asset_id, new_value=f"criticality={criticality};internet_exposed={internet_exposed}")

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
        asset = conn.execute("SELECT name FROM assets WHERE id = ?", (asset_id,)).fetchone()
        conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
        conn.close()
        record_audit("ASSET_DELETED", "asset", asset_id, old_value=f"name={asset['name']}" if asset else None)
        flash("Ativo removido.", "info")
        return redirect(url_for("assets"))
