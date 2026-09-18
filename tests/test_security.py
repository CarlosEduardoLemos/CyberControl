import io
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import app_modules.core as core
from cybercontrol import app, create_app


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.old_db_path = core.DB_PATH
        self.old_upload = app.config["UPLOAD_FOLDER"]
        core.DB_PATH = os.path.join(self.tmpdir, "test.db")
        app.config.update(TESTING=True, UPLOAD_FOLDER=os.path.join(self.tmpdir, "uploads"))
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        core.init_db()
        create_app()
        self.client = app.test_client()

    def tearDown(self):
        core.DB_PATH = self.old_db_path
        app.config["UPLOAD_FOLDER"] = self.old_upload
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def db_one(self, sql, params=()):
        with app.app_context():
            return core.get_db().execute(sql, params).fetchone()

    def db_exec(self, sql, params=()):
        with app.app_context():
            conn = core.get_db()
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.lastrowid

    def csrf_token(self, path="/register"):
        self.client.get(path)
        with self.client.session_transaction() as sess:
            return sess["_csrf_token"]

    def register_and_login_admin(self):
        token = self.csrf_token("/register")
        self.client.post("/register", data={"_csrf_token": token, "username": "admin", "password": "secret123"})
        token = self.csrf_token("/login")
        self.client.post("/login", data={"_csrf_token": token, "username": "admin", "password": "secret123"})

    def create_vulnerability(self, **extra):
        user_id = self.db_one("SELECT id FROM users WHERE username='admin'")["id"]
        asset_id = self.db_exec(
            "INSERT INTO assets (name, asset_type, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("srv", "Servidor", user_id, "2026-01-01T00:00:00"),
        )
        fields = {
            "cve_id": None,
            "due_date": "2026-02-01",
            "kev": 0,
        }
        fields.update(extra)
        vuln_id = self.db_exec(
            """INSERT INTO vulnerabilities
               (asset_id,title,cvss_score,severity,risk_score,risk_level,status,discovered_date,
                created_by,created_at,cve_id,due_date,kev)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (asset_id, "test", 5.0, "Média", 5.0, "Médio", "Aberta", "2026-01-01",
             user_id, "2026-01-01T00:00:00", fields["cve_id"], fields["due_date"], fields["kev"]),
        )
        return asset_id, vuln_id

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post("/register", data={"username": "x", "password": "12345678"})
        self.assertEqual(response.status_code, 400)

    def test_first_registered_user_is_admin(self):
        token = self.csrf_token("/register")
        self.client.post("/register", data={"_csrf_token": token, "username": "admin", "password": "secret123"})
        self.assertEqual(self.db_one("SELECT role FROM users WHERE username='admin'")["role"], "admin")

    def test_public_registration_closes_after_bootstrap(self):
        self.register_and_login_admin()
        token = self.csrf_token("/")
        self.client.post("/logout", data={"_csrf_token": token})
        self.assertEqual(self.client.get("/register").status_code, 302)

    def test_login_lockout_is_scoped_by_ip_and_username(self):
        token = self.csrf_token("/login")
        for _ in range(5):
            self.client.post("/login", data={"_csrf_token": token, "username": "missing", "password": "wrong-pass"})
        row = self.db_one(
            "SELECT locked_until FROM login_attempts WHERE ip_address=? AND username=?",
            ("127.0.0.1", "missing"),
        )
        self.assertGreater(datetime.fromisoformat(row["locked_until"]), datetime.now() - timedelta(seconds=1))
        self.assertIsNone(self.db_one(
            "SELECT locked_until FROM login_attempts WHERE ip_address=? AND username=?",
            ("127.0.0.1", "other"),
        ))

    def test_role_change_in_database_invalidates_old_admin_privilege(self):
        self.register_and_login_admin()
        admin_id = self.db_one("SELECT id FROM users WHERE username='admin'")["id"]
        self.db_exec("UPDATE users SET role='analista' WHERE id=?", (admin_id,))
        response = self.client.get("/users")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/"))

    def test_deleted_user_session_is_invalidated(self):
        self.register_and_login_admin()
        admin_id = self.db_one("SELECT id FROM users WHERE username='admin'")["id"]
        self.db_exec("DELETE FROM users WHERE id=?", (admin_id,))
        response = self.client.get("/assets")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))

    def test_csrf_token_rotates_after_login(self):
        token_before = self.csrf_token("/register")
        self.client.post("/register", data={"_csrf_token": token_before, "username": "admin", "password": "secret123"})
        login_token = self.csrf_token("/login")
        self.client.post("/login", data={"_csrf_token": login_token, "username": "admin", "password": "secret123"})
        self.client.get("/")
        with self.client.session_transaction() as sess:
            self.assertNotEqual(sess["_csrf_token"], login_token)

    def test_disallowed_evidence_extension_is_rejected(self):
        self.register_and_login_admin()
        asset_id, _ = self.create_vulnerability()
        token = self.csrf_token("/vulnerabilities/add")
        response = self.client.post(
            "/vulnerabilities/add",
            data={"_csrf_token": token, "asset_id": str(asset_id), "title": "upload inválido", "cvss_score": "5.0",
                  "evidence": (io.BytesIO(b"echo unsafe"), "script.bat")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.db_one("SELECT id FROM vulnerabilities WHERE title='upload inválido'"))

    def test_dashboard_does_not_fetch_external_feeds_automatically(self):
        self.register_and_login_admin()
        with patch("app_modules.live_vulns._fetch_live_vulnerabilities") as fetch_mock:
            response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        fetch_mock.assert_not_called()

    def test_migration_adds_vulnerability_management_columns(self):
        with app.app_context():
            columns = {row["name"] for row in core.get_db().execute("PRAGMA table_info(vulnerabilities)")}
        self.assertTrue({"cve_id", "cwe_id", "remediation", "assigned_to", "due_date", "kev", "updated_at"}.issubset(columns))


if __name__ == "__main__":
    unittest.main()
