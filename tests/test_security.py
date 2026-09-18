import io
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

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
        create_app()
        self.client = app.test_client()

    def tearDown(self):
        core.DB_PATH = self.old_db_path
        app.config["UPLOAD_FOLDER"] = self.old_upload
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def csrf_token(self, path="/register"):
        self.client.get(path)
        with self.client.session_transaction() as sess:
            return sess["_csrf_token"]

    def register_and_login_admin(self):
        token = self.csrf_token("/register")
        self.client.post("/register", data={
            "_csrf_token": token,
            "username": "admin",
            "password": "secret123",
        })
        token = self.csrf_token("/login")
        self.client.post("/login", data={
            "_csrf_token": token,
            "username": "admin",
            "password": "secret123",
        })

    def create_vulnerability(self):
        conn = core.get_db()
        user_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
        conn.execute(
            "INSERT INTO assets (name, asset_type, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("srv", "Servidor", user_id, "2026-01-01T00:00:00"),
        )
        asset_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.execute(
            """INSERT INTO vulnerabilities
               (asset_id, title, cvss_score, severity, status, discovered_date, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset_id, "test", 5.0, "Média", "Aberta", "2026-01-01", user_id, "2026-01-01T00:00:00"),
        )
        vuln_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        conn.commit()
        conn.close()
        return asset_id, vuln_id

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post("/register", data={"username": "x", "password": "12345678"})
        self.assertEqual(response.status_code, 400)

    def test_first_registered_user_is_admin(self):
        token = self.csrf_token("/register")
        self.client.post("/register", data={
            "_csrf_token": token,
            "username": "admin",
            "password": "secret123",
        })
        conn = core.get_db()
        user = conn.execute("SELECT role FROM users WHERE username = ?", ("admin",)).fetchone()
        conn.close()
        self.assertEqual(user["role"], "admin")

    def test_public_registration_closes_after_bootstrap(self):
        self.register_and_login_admin()
        token = self.csrf_token("/logout")
        self.client.post("/logout", data={"_csrf_token": token})
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))

    def test_admin_can_create_analyst_after_bootstrap(self):
        self.register_and_login_admin()
        token = self.csrf_token("/register")
        response = self.client.post("/register", data={
            "_csrf_token": token,
            "username": "analista1",
            "password": "secret456",
        })
        self.assertEqual(response.status_code, 302)
        conn = core.get_db()
        role = conn.execute("SELECT role FROM users WHERE username = 'analista1'").fetchone()["role"]
        conn.close()
        self.assertEqual(role, "analista")

    def test_login_lockout_is_persisted_in_database(self):
        token = self.csrf_token("/login")
        for _ in range(5):
            self.client.post("/login", data={
                "_csrf_token": token,
                "username": "missing",
                "password": "wrong-pass",
            })
        conn = core.get_db()
        row = conn.execute("SELECT locked_until FROM login_attempts WHERE ip_address = ?", ("127.0.0.1",)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertGreater(datetime.fromisoformat(row["locked_until"]), datetime.now() - timedelta(seconds=1))

    def test_evidence_path_traversal_is_not_served(self):
        self.register_and_login_admin()
        _, vuln_id = self.create_vulnerability()
        secret_path = os.path.join(self.tmpdir, "secret.txt")
        with open(secret_path, "w", encoding="utf-8") as file:
            file.write("not-for-download")
        response = self.client.get(f"/vulnerabilities/{vuln_id}/evidence/../../secret.txt")
        self.assertIn(response.status_code, (404, 308))
        self.assertNotIn(b"not-for-download", response.data)

    def test_invalid_status_is_not_persisted(self):
        self.register_and_login_admin()
        _, vuln_id = self.create_vulnerability()
        token = self.csrf_token(f"/vulnerabilities/{vuln_id}/edit")
        self.client.post(
            f"/vulnerabilities/{vuln_id}/edit",
            data={"_csrf_token": token, "status": "INJETADO"},
        )
        conn = core.get_db()
        status = conn.execute("SELECT status FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "Aberta")

    def test_disallowed_evidence_extension_is_rejected(self):
        self.register_and_login_admin()
        asset_id, _ = self.create_vulnerability()
        token = self.csrf_token("/vulnerabilities/add")
        response = self.client.post(
            "/vulnerabilities/add",
            data={
                "_csrf_token": token,
                "asset_id": str(asset_id),
                "title": "upload inválido",
                "cvss_score": "5.0",
                "evidence": (io.BytesIO(b"echo unsafe"), "script.bat"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)
        conn = core.get_db()
        exists = conn.execute("SELECT id FROM vulnerabilities WHERE title = ?", ("upload inválido",)).fetchone()
        conn.close()
        self.assertIsNone(exists)

    def test_deleting_vulnerability_removes_evidence_directory(self):
        self.register_and_login_admin()
        _, vuln_id = self.create_vulnerability()
        evidence_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(vuln_id))
        os.makedirs(evidence_dir, exist_ok=True)
        with open(os.path.join(evidence_dir, "proof.txt"), "w", encoding="utf-8") as file:
            file.write("evidence")
        token = self.csrf_token("/vulnerabilities")
        self.client.post(
            f"/vulnerabilities/{vuln_id}/delete",
            data={"_csrf_token": token},
        )
        self.assertFalse(os.path.exists(evidence_dir))

    def test_invalid_report_filters_are_ignored(self):
        self.register_and_login_admin()
        response = self.client.get("/reports/pdf?severity=INVALID&status=INVALID")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")


if __name__ == "__main__":
    unittest.main()
