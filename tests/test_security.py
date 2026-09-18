import os
import shutil
import tempfile
import unittest

import app_modules.core as core
from cybercontrol import app, create_app


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        create_app()
        self.tmpdir = tempfile.mkdtemp()
        self.old_db_path = core.DB_PATH
        self.old_upload = app.config["UPLOAD_FOLDER"]
        core.DB_PATH = os.path.join(self.tmpdir, "test.db")
        app.config.update(TESTING=True, UPLOAD_FOLDER=os.path.join(self.tmpdir, "uploads"))
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        core.init_db()
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

    def test_post_without_csrf_is_rejected(self):
        response = self.client.post("/register", data={"username": "x", "password": "y"})
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

    def test_evidence_path_traversal_is_not_served(self):
        self.register_and_login_admin()
        conn = core.get_db()
        user_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
        conn.execute(
            "INSERT INTO assets (name, asset_type, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("srv", "Servidor", user_id, "2026-01-01T00:00:00"),
        )
        asset_id = conn.execute("SELECT id FROM assets").fetchone()["id"]
        conn.execute(
            """INSERT INTO vulnerabilities
               (asset_id, title, cvss_score, severity, status, discovered_date, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset_id, "test", 5.0, "Média", "Aberta", "2026-01-01", user_id, "2026-01-01T00:00:00"),
        )
        vuln_id = conn.execute("SELECT id FROM vulnerabilities").fetchone()["id"]
        conn.commit()
        conn.close()

        secret_path = os.path.join(self.tmpdir, "secret.txt")
        with open(secret_path, "w", encoding="utf-8") as f:
            f.write("not-for-download")

        response = self.client.get(
            f"/vulnerabilities/{vuln_id}/evidence/../../secret.txt"
        )
        self.assertIn(response.status_code, (404, 308))
        self.assertNotIn(b"not-for-download", response.data)

    def test_invalid_status_is_not_persisted(self):
        self.register_and_login_admin()
        conn = core.get_db()
        user_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]
        conn.execute(
            "INSERT INTO assets (name, asset_type, created_by, created_at) VALUES (?, ?, ?, ?)",
            ("srv", "Servidor", user_id, "2026-01-01T00:00:00"),
        )
        asset_id = conn.execute("SELECT id FROM assets").fetchone()["id"]
        conn.execute(
            """INSERT INTO vulnerabilities
               (asset_id, title, cvss_score, severity, status, discovered_date, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (asset_id, "test", 5.0, "Média", "Aberta", "2026-01-01", user_id, "2026-01-01T00:00:00"),
        )
        vuln_id = conn.execute("SELECT id FROM vulnerabilities").fetchone()["id"]
        conn.commit()
        conn.close()

        token = self.csrf_token(f"/vulnerabilities/{vuln_id}/edit")
        self.client.post(
            f"/vulnerabilities/{vuln_id}/edit",
            data={"_csrf_token": token, "status": "INJETADO"},
        )
        conn = core.get_db()
        status = conn.execute("SELECT status FROM vulnerabilities WHERE id = ?", (vuln_id,)).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "Aberta")


if __name__ == "__main__":
    unittest.main()
