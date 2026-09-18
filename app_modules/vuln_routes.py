import io
import os
import re
import shutil
import uuid
from datetime import date, datetime

from flask import flash, redirect, render_template, request, send_file, send_from_directory, session, url_for
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.utils import secure_filename

from app_modules.audit import record_audit
from app_modules.core import (
    VALID_SEVERITIES,
    VALID_STATUSES,
    admin_required,
    app,
    cvss_to_severity,
    get_db,
    login_required,
)
from app_modules.live_vulns import known_kev_ids
from app_modules.risk import calculate_risk_score, risk_level
from app_modules.sla import default_due_date, sla_status

ALLOWED_EVIDENCE_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "pdf", "txt", "log", "csv", "json"})
VALID_SOURCES = frozenset({"Manual", "NVD", "CISA KEV", "Pentest", "Scanner", "Bug Bounty", "Outro"})
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


def _allowed_evidence(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EVIDENCE_EXTENSIONS


def _normalize_identifier(value, pattern, label):
    value = (value or "").strip().upper()
    if value and not pattern.match(value):
        raise ValueError(f"{label} inválido.")
    return value or None


def _validated_filters():
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    sla = request.args.get("sla", "").strip()
    kev = request.args.get("kev", "").strip()
    if severity and severity not in VALID_SEVERITIES:
        severity = ""
    if status and status not in VALID_STATUSES:
        status = ""
    if sla not in {"", "vencido", "proximo", "dentro"}:
        sla = ""
    if kev not in {"", "1"}:
        kev = ""
    return severity, status, sla, kev


def _serialize_vulnerability_form(request_form, asset, current=None):
    title = request_form.get("title", "").strip() or (current["title"] if current else "")
    description = request_form.get("description", "").strip()
    remediation = request_form.get("remediation", "").strip()
    assigned_to = request_form.get("assigned_to", "").strip()
    source = request_form.get("source", "Manual").strip()
    discovered_date = request_form.get("discovered_date") or (current["discovered_date"] if current else date.today().isoformat())
    due_date = request_form.get("due_date", "").strip()
    status = request_form.get("status", current["status"] if current else "Aberta")
    if not title:
        raise ValueError("O título da vulnerabilidade é obrigatório.")
    if source not in VALID_SOURCES:
        raise ValueError("Origem inválida.")
    if status not in VALID_STATUSES:
        raise ValueError("Status inválido.")
    try:
        datetime.strptime(discovered_date, "%Y-%m-%d")
        if due_date:
            datetime.strptime(due_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("Data inválida.") from exc

    cve_id = _normalize_identifier(request_form.get("cve_id"), CVE_RE, "CVE")
    cwe_id = _normalize_identifier(request_form.get("cwe_id"), CWE_RE, "CWE")
    try:
        cvss_score = round(float(request_form.get("cvss_score", current["cvss_score"] if current else 0)), 1)
        if not 0 <= cvss_score <= 10:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError("Score CVSS inválido. Use um valor entre 0.0 e 10.0.") from exc

    severity = cvss_to_severity(cvss_score)
    if not due_date:
        due_date = default_due_date(discovered_date, severity)
    kev = bool(cve_id and cve_id in known_kev_ids()) or bool(current and current["kev"])
    risk_score = calculate_risk_score(
        cvss_score,
        asset["criticality"],
        bool(asset["internet_exposed"]),
        kev,
    )
    return {
        "title": title,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "risk_score": risk_score,
        "risk_level": risk_level(risk_score),
        "status": status,
        "discovered_date": discovered_date,
        "resolved_date": date.today().isoformat() if status == "Resolvida" else None,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "source": source,
        "remediation": remediation,
        "assigned_to": assigned_to,
        "due_date": due_date,
        "kev": 1 if kev else 0,
    }


def _decorate_sla(rows):
    items = []
    for row in rows:
        item = dict(row)
        item["sla_status"] = sla_status(item.get("due_date"), item.get("status"))
        items.append(item)
    return items


def register_vuln_routes():
    @app.route("/vulnerabilities")
    @login_required
    def vulnerabilities():
        severity_filter, status_filter, sla_filter, kev_filter = _validated_filters()
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
        if kev_filter:
            query += " AND v.kev = 1"
        if sla_filter == "vencido":
            query += " AND v.status != 'Resolvida' AND v.due_date < date('now')"
        elif sla_filter == "proximo":
            query += " AND v.status != 'Resolvida' AND v.due_date BETWEEN date('now') AND date('now', '+3 days')"
        elif sla_filter == "dentro":
            query += " AND v.status != 'Resolvida' AND v.due_date > date('now', '+3 days')"
        query += " ORDER BY v.risk_score DESC, v.cvss_score DESC"

        vulns = _decorate_sla(get_db().execute(query, params).fetchall())
        return render_template(
            "vulnerabilities.html",
            vulns=vulns,
            severity_filter=severity_filter,
            status_filter=status_filter,
            sla_filter=sla_filter,
            kev_filter=kev_filter,
        )

    @app.route("/vulnerabilities/add", methods=["GET", "POST"])
    @login_required
    def add_vulnerability():
        conn = get_db()
        all_assets = conn.execute("SELECT id, name FROM assets ORDER BY name").fetchall()
        if request.method == "POST":
            asset_id = request.form.get("asset_id", "").strip()
            asset = conn.execute(
                "SELECT id, criticality, internet_exposed FROM assets WHERE id = ?", (asset_id,)
            ).fetchone()
            if not asset:
                flash("Ativo inválido.", "danger")
                return redirect(url_for("add_vulnerability"))
            try:
                data = _serialize_vulnerability_form(request.form, asset)
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("add_vulnerability", asset_id=asset_id))

            evidence_file = request.files.get("evidence")
            original_name = None
            if evidence_file and evidence_file.filename:
                original_name = secure_filename(evidence_file.filename)
                if not original_name or not _allowed_evidence(original_name):
                    allowed = ", ".join(sorted(ALLOWED_EVIDENCE_EXTENSIONS))
                    flash(f"Tipo de evidência não permitido. Use: {allowed}.", "danger")
                    return redirect(url_for("add_vulnerability", asset_id=asset_id))

            now = datetime.now().isoformat()
            cursor = conn.execute("""
                INSERT INTO vulnerabilities (
                    asset_id, title, description, cvss_score, severity, risk_score, risk_level,
                    status, discovered_date, resolved_date, created_by, created_at, updated_at,
                    cve_id, cwe_id, source, remediation, assigned_to, due_date, kev
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                asset_id, data["title"], data["description"], data["cvss_score"], data["severity"],
                data["risk_score"], data["risk_level"], data["status"], data["discovered_date"],
                data["resolved_date"], session["user_id"], now, now, data["cve_id"], data["cwe_id"],
                data["source"], data["remediation"], data["assigned_to"], data["due_date"], data["kev"],
            ))
            vuln_id = cursor.lastrowid
            evidence_dir = None
            try:
                if original_name:
                    evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
                    os.makedirs(evidence_dir, exist_ok=True)
                    filename = f"{uuid.uuid4().hex}_{original_name}"
                    evidence_file.save(os.path.join(evidence_dir, filename))
                conn.commit()
            except OSError:
                conn.rollback()
                if evidence_dir:
                    shutil.rmtree(evidence_dir, ignore_errors=True)
                flash("Não foi possível salvar a evidência. Nenhum registro foi criado.", "danger")
                return redirect(url_for("add_vulnerability", asset_id=asset_id))

            record_audit(
                "VULNERABILITY_CREATED", "vulnerability", vuln_id,
                new_value=f"cvss={data['cvss_score']};risk={data['risk_score']};kev={data['kev']}",
            )
            flash("Vulnerabilidade registrada com sucesso.", "success")
            return redirect(url_for("vulnerabilities"))

        return render_template(
            "add_vulnerability.html",
            assets=all_assets,
            preselected_asset=request.args.get("asset_id", ""),
            allowed_evidence_extensions=sorted(ALLOWED_EVIDENCE_EXTENSIONS),
            valid_sources=sorted(VALID_SOURCES),
        )

    @app.route("/vulnerabilities/<int:vuln_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_vulnerability(vuln_id):
        conn = get_db()
        vuln = conn.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        if not vuln:
            flash("Vulnerabilidade não encontrada.", "danger")
            return redirect(url_for("vulnerabilities"))
        asset = conn.execute(
            "SELECT id, criticality, internet_exposed FROM assets WHERE id = ?", (vuln["asset_id"],)
        ).fetchone()

        if request.method == "POST":
            try:
                data = _serialize_vulnerability_form(request.form, asset, current=vuln)
            except ValueError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("edit_vulnerability", vuln_id=vuln_id))
            old_snapshot = f"status={vuln['status']};risk={vuln['risk_score']};cve={vuln['cve_id'] or ''}"
            conn.execute("""
                UPDATE vulnerabilities SET
                    title = ?, description = ?, cvss_score = ?, severity = ?, risk_score = ?,
                    risk_level = ?, status = ?, discovered_date = ?, resolved_date = ?, cve_id = ?,
                    cwe_id = ?, source = ?, remediation = ?, assigned_to = ?, due_date = ?, kev = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                data["title"], data["description"], data["cvss_score"], data["severity"], data["risk_score"],
                data["risk_level"], data["status"], data["discovered_date"], data["resolved_date"],
                data["cve_id"], data["cwe_id"], data["source"], data["remediation"], data["assigned_to"],
                data["due_date"], data["kev"], datetime.now().isoformat(), vuln_id,
            ))
            conn.commit()
            record_audit(
                "VULNERABILITY_UPDATED", "vulnerability", vuln_id,
                old_value=old_snapshot,
                new_value=f"status={data['status']};risk={data['risk_score']};cve={data['cve_id'] or ''}",
            )
            flash("Vulnerabilidade atualizada.", "success")
            return redirect(url_for("vulnerabilities"))

        evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
        evidence_files = []
        if os.path.isdir(evidence_dir):
            evidence_files = sorted(
                name for name in os.listdir(evidence_dir)
                if os.path.isfile(os.path.join(evidence_dir, name))
            )
        return render_template(
            "edit_vulnerability.html",
            vuln=vuln,
            evidence_files=evidence_files,
            vuln_id=vuln_id,
            valid_sources=sorted(VALID_SOURCES),
            sla_status=sla_status(vuln["due_date"], vuln["status"]),
        )

    @app.route("/vulnerabilities/<int:vuln_id>/delete", methods=["POST"])
    @admin_required
    def delete_vulnerability(vuln_id):
        conn = get_db()
        vuln = conn.execute("SELECT title FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        if not vuln:
            flash("Vulnerabilidade não encontrada.", "warning")
            return redirect(url_for("vulnerabilities"))
        conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
        conn.commit()
        shutil.rmtree(os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id)), ignore_errors=True)
        record_audit("VULNERABILITY_DELETED", "vulnerability", vuln_id, old_value=f"title={vuln['title']}")
        flash("Vulnerabilidade removida.", "info")
        return redirect(url_for("vulnerabilities"))

    @app.route("/vulnerabilities/<int:vuln_id>/evidence/<path:filename>")
    @login_required
    def download_evidence(vuln_id, filename):
        vuln_exists = get_db().execute("SELECT id FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()
        if not vuln_exists:
            flash("Vulnerabilidade não encontrada.", "danger")
            return redirect(url_for("vulnerabilities"))
        evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
        return send_from_directory(evidence_dir, filename, as_attachment=True)

    @app.route("/reports/pdf")
    @login_required
    def report_pdf():
        severity_filter, status_filter, _sla_filter, _kev_filter = _validated_filters()
        query = """
            SELECT v.*, a.name AS asset_name, a.ip_address
            FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id WHERE 1=1
        """
        params = []
        if severity_filter:
            query += " AND v.severity = ?"
            params.append(severity_filter)
        if status_filter:
            query += " AND v.status = ?"
            params.append(status_filter)
        query += " ORDER BY v.risk_score DESC, v.cvss_score DESC"
        vulns = _decorate_sla(get_db().execute(query, params).fetchall())

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), topMargin=1.5 * cm, bottomMargin=1.5 * cm)
        styles = getSampleStyleSheet()
        elements = [Paragraph("Relatório de Vulnerabilidades", ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=18))]
        elements.append(Paragraph(f"Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles["Normal"]))
        elements.append(Spacer(1, 0.4 * cm))
        data = [["Ativo", "CVE", "Vulnerabilidade", "CVSS", "Risco", "Status", "SLA", "Prazo"]]
        for vuln in vulns:
            data.append([
                vuln["asset_name"], vuln.get("cve_id") or "-", vuln["title"], f'{vuln["cvss_score"]:.1f}',
                f'{vuln["risk_level"]} {vuln["risk_score"]:.1f}', vuln["status"], vuln["sla_status"], vuln.get("due_date") or "-",
            ])
        table = Table(data, repeatRows=1, colWidths=[3 * cm, 3 * cm, 6 * cm, 1.5 * cm, 2.5 * cm, 2.7 * cm, 3.2 * cm, 2.5 * cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#212529")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ]))
        elements.append(table)
        doc.build(elements)
        buffer.seek(0)
        filename = f"relatorio_vulnerabilidades_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")
