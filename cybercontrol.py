import os

from app_modules.auth_routes import register_auth_routes
from app_modules.asset_routes import register_asset_routes
from app_modules.audit_routes import register_audit_routes
from app_modules.core import app, init_db
from app_modules.dashboard_routes import register_dashboard_routes
from app_modules.live_vulns import refresh_live_vulnerabilities
from app_modules.user_routes import register_user_routes
from app_modules.vuln_routes import register_vuln_routes


def create_app():
    if getattr(app, "_routes_registered", False):
        return app

    register_auth_routes()
    register_dashboard_routes()
    register_asset_routes()
    register_vuln_routes()
    register_user_routes()
    register_audit_routes()
    app._routes_registered = True
    return app


create_app()


if __name__ == "__main__":
    init_db()
    refresh_live_vulnerabilities(force=True)
    debug_enabled = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes", "on"}
    app.run(debug=debug_enabled)
