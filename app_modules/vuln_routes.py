import io
import os
from datetime import datetime

from flask import flash, redirect, render_template, request, send_file, session, url_for
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app_modules.core import app, get_db, login_required, admin_required, cvss_to_severity


def register_vuln_routes():
    @app.route("/vulnerabilities")
    @login_required
    def vulnerabilities():
        severity_filter = request.args.get("severity", "")
        status_filter = request.args.get("status", "")

        query = """
            SELECT v.*, a.name AS asset_name
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE 1=1
        """
        params = []
        if severity_filter:
            query += " AND v.severity = ?"
            params.append(severity_filter)
        if status_filter:
            query += " AND v.status = ?"
            params.append(status_filter)
        query += " ORDER BY v.cvss_score DESC"

        conn = get_db()
        vulns = conn.execute(query, params).fetchall()
        conn.close()

        return render_template(
            "vulnerabilities.html",
            vulns=vulns,
            severity_filter=severity_filter,
            status_filter=status_filter,
        )

    @app.route("/vulnerabilities/add", methods=["GET", "POST"])
    @login_required
    def add_vulnerability():
        conn = get_db()
        all_assets = conn.execute("SELECT id, name FROM assets ORDER BY name").fetchall()

        if request.method == "POST":
            asset_id = request.form["asset_id"]
            title = request.form["title"].strip()
            description = request.form.get("description", "").strip()
            cvss_score = request.form.get("cvss_score", "0")
            discovered_date = request.form.get("discovered_date") or datetime.now().strftime("%Y-%m-%d")
            evidence_file = request.files.get("evidence")

            try:
                cvss_score = round(float(cvss_score), 1)
                if not (0 <= cvss_score <= 10):
                    raise ValueError
            except ValueError:
                flash("Score CVSS inválido. Use um valor entre 0.0 e 10.0.", "danger")
                conn.close()
                return redirect(url_for("add_vulnerability"))

            if not title or not asset_id:
                flash("Preencha o ativo e o título da vulnerabilidade.", "danger")
                conn.close()
                return redirect(url_for("add_vulnerability"))

            severity = cvss_to_severity(cvss_score)
            evidence_path = None
            if evidence_file and evidence_file.filename:
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{evidence_file.filename}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                evidence_file.save(save_path)
                evidence_path = filename

            cursor = conn.execute("""
                INSERT INTO vulnerabilities
                    (asset_id, title, description, cvss_score, severity, status, discovered_date, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, 'Aberta', ?, ?, ?)
            """, (asset_id, title, description, cvss_score, severity, discovered_date,
                  session["user_id"], datetime.now().isoformat()))
            vuln_id = cursor.lastrowid
            conn.commit()
            conn.close()

            if evidence_path:
                evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
                os.makedirs(evidence_dir, exist_ok=True)
                os.replace(os.path.join(app.config["UPLOAD_FOLDER"], evidence_path), os.path.join(evidence_dir, evidence_path))

            flash("Vulnerabilidade registrada com sucesso.", "success")
            return redirect(url_for("vulnerabilities"))

        conn.close()
        preselected_asset = request.args.get("asset_id", "")
        return render_template("add_vulnerability.html", assets=all_assets, preselected_asset=preselected_asset)

    @app.route("/vulnerabilities/<int:vuln_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_vulnerability(vuln_id):
        conn = get_db()
        vuln = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        if not vuln:
            conn.close()
            flash("Vulnerabilidade não encontrada.", "danger")
            return redirect(url_for("vulnerabilities"))

        if request.method == "POST":
            status = request.form["status"]
            resolved_date = None
            if status == "Resolvida":
                resolved_date = datetime.now().strftime("%Y-%m-%d")

            conn.execute("""
                UPDATE vulnerabilities SET status = ?, resolved_date = ? WHERE id = ?
            """, (status, resolved_date, vuln_id))
            conn.commit()
            conn.close()

            flash("Status atualizado.", "success")
            return redirect(url_for("vulnerabilities"))

        evidence_files = []
        evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
        if os.path.isdir(evidence_dir):
            evidence_files = sorted(os.listdir(evidence_dir))

        conn.close()
        return render_template("edit_vulnerability.html", vuln=vuln, evidence_files=evidence_files, vuln_id=vuln_id)

    @app.route("/vulnerabilities/<int:vuln_id>/delete", methods=["POST"])
    @admin_required
    def delete_vulnerability(vuln_id):
        conn = get_db()
        conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
        conn.commit()
        conn.close()
        flash("Vulnerabilidade removida.", "info")
        return redirect(url_for("vulnerabilities"))

    @app.route("/vulnerabilities/<int:vuln_id>/evidence/<path:filename>")
    @login_required
    def download_evidence(vuln_id, filename):
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id), filename)
        if not os.path.isfile(file_path):
            flash("Evidência não encontrada.", "danger")
            return redirect(url_for("vulnerabilities"))
        return send_file(file_path, as_attachment=True, download_name=filename)

    @app.route("/reports/pdf")
    @login_required
    def report_pdf():
        severity_filter = request.args.get("severity", "")
        status_filter = request.args.get("status", "")

        query = """
            SELECT v.*, a.name AS asset_name, a.ip_address
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            WHERE 1=1
        """
        params = []
        if severity_filter:
            query += " AND v.severity = ?"
            params.append(severity_filter)
        if status_filter:
            query += " AND v.status = ?"
            params.append(status_filter)
        query += " ORDER BY v.cvss_score DESC"

        conn = get_db()
        vulns = conn.execute(query, params).fetchall()
        conn.close()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=18)
        subtitle_style = ParagraphStyle("Subtitle", parent=styles["Normal"], fontSize=10, textColor=colors.grey)

        elements = []
        elements.append(Paragraph("Relatório de Vulnerabilidades", title_style))
        gerado_em = datetime.now().strftime("%d/%m/%Y %H:%M")
        filtros_txt = []
        if severity_filter:
            filtros_txt.append(f"Severidade: {severity_filter}")
        if status_filter:
            filtros_txt.append(f"Status: {status_filter}")
        filtros_str = " | ".join(filtros_txt) if filtros_txt else "Sem filtros"
        elements.append(Paragraph(f"Gerado em {gerado_em} — {filtros_str}", subtitle_style))
        elements.append(Spacer(1, 0.6 * cm))

        summary = {}
        for v in vulns:
            summary[v["severity"]] = summary.get(v["severity"], 0) + 1
        summary_line = "  |  ".join(f"{sev}: {summary.get(sev, 0)}" for sev in ["Crítica", "Alta", "Média", "Baixa"])
        elements.append(Paragraph(f"<b>Total de vulnerabilidades:</b> {len(vulns)}", styles["Normal"]))
        elements.append(Paragraph(summary_line, styles["Normal"]))
        elements.append(Spacer(1, 0.6 * cm))

        data = [["Ativo", "Vulnerabilidade", "CVSS", "Severidade", "Status", "Descoberta"]]
        for v in vulns:
            data.append([
                v["asset_name"],
                v["title"],
                f'{v["cvss_score"]:.1f}',
                v["severity"],
                v["status"],
                v["discovered_date"],
            ])

        table = Table(data, repeatRows=1, colWidths=[3.2 * cm, 5 * cm, 1.5 * cm, 2.3 * cm, 2.5 * cm, 2.5 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ]))
        elements.append(table)

        doc.build(elements)
        buffer.seek(0)

        filename = f"relatorio_vulnerabilidades_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")
