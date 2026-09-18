from datetime import date

from flask import flash, redirect, render_template, request, url_for

from app_modules.audit import record_audit
from app_modules.core import SEVERITY_ORDER, app, get_db, login_required
from app_modules.live_vulns import (
    cache_metadata,
    cached_live_vulnerabilities,
    known_kev_ids,
    refresh_live_vulnerabilities,
    summarize_live_vulnerabilities,
)
from app_modules.risk import calculate_risk_score, risk_level


def _sync_kev_flags(conn):
    kev_ids = known_kev_ids()
    if not kev_ids:
        return 0
    rows = conn.execute("""
        SELECT v.id, v.cve_id, v.cvss_score, v.risk_score, v.kev, a.criticality, a.internet_exposed
        FROM vulnerabilities v
        JOIN assets a ON a.id = v.asset_id
        WHERE v.cve_id IS NOT NULL AND v.cve_id != ''
    """).fetchall()
    updated = 0
    for row in rows:
        is_kev = row["cve_id"].upper() in kev_ids
        new_risk = calculate_risk_score(
            row["cvss_score"], row["criticality"], bool(row["internet_exposed"]), is_kev
        )
        if bool(row["kev"]) != is_kev or new_risk != row["risk_score"]:
            conn.execute(
                "UPDATE vulnerabilities SET kev = ?, risk_score = ?, risk_level = ?, updated_at = datetime('now') WHERE id = ?",
                (1 if is_kev else 0, new_risk, risk_level(new_risk), row["id"]),
            )
            updated += 1
    conn.commit()
    return updated


def register_dashboard_routes():
    @app.route("/threat-intel/refresh", methods=["POST"])
    @login_required
    def refresh_threat_intel():
        _records, error = refresh_live_vulnerabilities(force=True, limit=8)
        updated = _sync_kev_flags(get_db())
        record_audit("THREAT_INTEL_REFRESH", "integration", None, new_value=f"kev_synced={updated}")
        if error:
            flash(f"Feeds atualizados parcialmente: {error}", "warning")
        else:
            flash(f"Feeds atualizados. {updated} vulnerabilidade(s) local(is) sincronizada(s) com CISA KEV.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/")
    @login_required
    def dashboard():
        conn = get_db()
        total_assets = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
        total_vulns = conn.execute("SELECT COUNT(*) AS c FROM vulnerabilities").fetchone()["c"]
        open_vulns = conn.execute("SELECT COUNT(*) AS c FROM vulnerabilities WHERE status != 'Resolvida'").fetchone()["c"]
        overdue_vulns = conn.execute(
            "SELECT COUNT(*) AS c FROM vulnerabilities WHERE status != 'Resolvida' AND due_date IS NOT NULL AND due_date < date('now')"
        ).fetchone()["c"]
        kev_open = conn.execute(
            "SELECT COUNT(*) AS c FROM vulnerabilities WHERE status != 'Resolvida' AND kev = 1"
        ).fetchone()["c"]
        avg_resolution = conn.execute("""
            SELECT AVG(julianday(resolved_date) - julianday(discovered_date)) AS days
            FROM vulnerabilities
            WHERE status = 'Resolvida' AND resolved_date IS NOT NULL
        """).fetchone()["days"]

        by_severity = conn.execute(
            "SELECT severity, COUNT(*) AS total FROM vulnerabilities GROUP BY severity"
        ).fetchall()
        severity_counts = {row["severity"]: row["total"] for row in by_severity}
        by_status = conn.execute(
            "SELECT status, COUNT(*) AS total FROM vulnerabilities GROUP BY status"
        ).fetchall()
        status_counts = {row["status"]: row["total"] for row in by_status}

        recent_vulns = conn.execute("""
            SELECT v.*, a.name AS asset_name
            FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
            ORDER BY v.created_at DESC LIMIT 8
        """).fetchall()
        top_assets = conn.execute("""
            SELECT a.id, a.name,
                   COUNT(v.id) AS vuln_count,
                   SUM(CASE WHEN v.status != 'Resolvida' THEN 1 ELSE 0 END) AS open_count,
                   COALESCE(MAX(v.risk_score), 0) AS max_risk
            FROM assets a
            LEFT JOIN vulnerabilities v ON v.asset_id = a.id
            GROUP BY a.id, a.name
            ORDER BY open_count DESC, max_risk DESC, vuln_count DESC
            LIMIT 5
        """).fetchall()
        monthly = conn.execute("""
            SELECT substr(discovered_date, 1, 7) AS month, COUNT(*) AS total
            FROM vulnerabilities
            WHERE discovered_date >= date('now', '-5 months', 'start of month')
            GROUP BY month ORDER BY month
        """).fetchall()
        remediation_backlog = conn.execute("""
            SELECT assigned_to, COUNT(*) AS total
            FROM vulnerabilities
            WHERE status != 'Resolvida' AND assigned_to IS NOT NULL AND trim(assigned_to) != ''
            GROUP BY assigned_to ORDER BY total DESC LIMIT 5
        """).fetchall()

        search_term = request.args.get("search_term", "").strip()
        source_filter = request.args.get("source_filter", "").strip()
        severity_filter = request.args.get("severity_filter", "").strip()
        live_vulns, live_vulns_error = cached_live_vulnerabilities(
            search_term=search_term,
            source_filter=source_filter,
            severity_filter=severity_filter,
        )
        live_vulns_summary = summarize_live_vulnerabilities(live_vulns)
        threat_meta = cache_metadata()
        max_monthly = max([row["total"] for row in monthly], default=1)

        return render_template(
            "dashboard.html",
            total_assets=total_assets,
            total_vulns=total_vulns,
            open_vulns=open_vulns,
            overdue_vulns=overdue_vulns,
            kev_open=kev_open,
            avg_resolution=round(avg_resolution, 1) if avg_resolution is not None else None,
            avg_resolution_display=f"{round(avg_resolution, 1)} dias" if avg_resolution is not None else "-",
            severity_counts=severity_counts,
            status_counts=status_counts,
            recent_vulns=recent_vulns,
            top_assets=top_assets,
            monthly=monthly,
            max_monthly=max_monthly,
            remediation_backlog=remediation_backlog,
            severity_order=SEVERITY_ORDER,
            live_vulns=live_vulns,
            live_vulns_error=live_vulns_error,
            search_term=search_term,
            source_filter=source_filter,
            severity_filter=severity_filter,
            live_vulns_summary=live_vulns_summary,
            threat_meta=threat_meta,
            today=date.today().isoformat(),
        )
