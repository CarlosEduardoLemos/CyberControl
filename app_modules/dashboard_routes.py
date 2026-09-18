from flask import render_template, request

from app_modules.core import SEVERITY_ORDER, app, get_db, login_required
from app_modules.live_vulns import refresh_live_vulnerabilities, summarize_live_vulnerabilities


def register_dashboard_routes():
    @app.route("/")
    @login_required
    def dashboard():
        conn = get_db()
        total_assets = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
        total_vulns = conn.execute("SELECT COUNT(*) AS c FROM vulnerabilities").fetchone()["c"]
        by_severity = conn.execute("SELECT severity, COUNT(*) AS total FROM vulnerabilities GROUP BY severity").fetchall()
        severity_counts = {row["severity"]: row["total"] for row in by_severity}
        by_status = conn.execute("SELECT status, COUNT(*) AS total FROM vulnerabilities GROUP BY status").fetchall()
        status_counts = {row["status"]: row["total"] for row in by_status}
        recent_vulns = conn.execute("""
            SELECT v.*, a.name AS asset_name
            FROM vulnerabilities v
            JOIN assets a ON a.id = v.asset_id
            ORDER BY v.created_at DESC
            LIMIT 8
        """).fetchall()
        conn.close()

        search_term = request.args.get("search_term", "").strip()
        source_filter = request.args.get("source_filter", "").strip()
        severity_filter = request.args.get("severity_filter", "").strip()
        live_vulns, live_vulns_error = refresh_live_vulnerabilities(
            search_term=search_term,
            source_filter=source_filter,
            severity_filter=severity_filter,
        )
        live_vulns_summary = summarize_live_vulnerabilities(live_vulns)
        return render_template(
            "dashboard.html",
            total_assets=total_assets,
            total_vulns=total_vulns,
            severity_counts=severity_counts,
            status_counts=status_counts,
            recent_vulns=recent_vulns,
            severity_order=SEVERITY_ORDER,
            live_vulns=live_vulns,
            live_vulns_error=live_vulns_error,
            search_term=search_term,
            source_filter=source_filter,
            severity_filter=severity_filter,
            live_vulns_summary=live_vulns_summary,
        )
