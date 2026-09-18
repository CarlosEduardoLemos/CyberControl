from datetime import datetime

from flask import request, session

from app_modules.core import get_db


def record_audit(action, resource_type, resource_id=None, old_value=None, new_value=None):
    """Registra uma ação relevante para rastreabilidade e investigação."""
    user_id = session.get("user_id")
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_logs
            (user_id, action, resource_type, resource_id, old_value, new_value,
             ip_address, user_agent, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            action,
            resource_type,
            resource_id,
            old_value,
            new_value,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", "")[:500],
            datetime.now().isoformat(),
        ),
    )
    conn.commit()
