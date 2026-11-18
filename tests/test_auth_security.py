"""
Regression tests for authentication & account-security fixes (PR #1).

Run:  python -m unittest discover -s tests -v
Every test runs against a throwaway SQLite database; the real oasis.sqlite3
is never touched.
"""

import contextlib
import io
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import core.database as database  # noqa: E402
import core.security as security  # noqa: E402

_ENV_KEYS = (
    "OASIS_DEV_MODE", "OASIS_ENV", "APP_ENV", "ENVIRONMENT",
    "OASIS_SMTP_HOST", "OASIS_SMTP_USER", "OASIS_SMTP_PASS",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_PASSWORD", "SMTP_FROM_EMAIL",
    "PROD_SMTP_HOST", "PROD_SMTP_PORT", "PROD_SMTP_USER", "PROD_SMTP_PASS", "PROD_SMTP_PASSWORD", "PROD_SMTP_FROM_EMAIL",
    "DEV_SMTP_HOST", "DEV_SMTP_PORT", "DEV_SMTP_USER", "DEV_SMTP_PASS", "DEV_SMTP_PASSWORD", "DEV_SMTP_FROM_EMAIL",
)


class _TempDbCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "test.sqlite3"
        self._orig_db = database.DB_PATH
        database.DB_PATH = self.db_path
        self._saved_env = {k: os.environ.pop(k, None) for k in _ENV_KEYS}
        security.CREDENTIALS_CHANGED_AT.clear()
        security._FAILED_LOGIN_ATTEMPTS.clear()

    def tearDown(self):
        database.DB_PATH = self._orig_db
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def migrate(self):
        from migrations.migrate import run_migrations
        with contextlib.redirect_stdout(io.StringIO()):
            return run_migrations(self.db_path)

    def raw(self, sql, params=()):
        with sqlite3.connect(self.db_path) as c:
            return c.execute(sql, params).fetchall()


class MigrationTests(_TempDbCase):
    def test_fresh_migration_hashes_seed_passwords(self):
        self.assertEqual(self.migrate(), 3)
        rows = self.raw("SELECT username, email, password FROM users ORDER BY id")
        self.assertEqual(len(rows), 4)
        for username, email, pwd in rows:
            self.assertTrue(email, f"{username} missing email")
            self.assertTrue(pwd.startswith("pbkdf2_sha256$"), f"{username} password not hashed")

    def test_migrations_are_idempotent(self):
        self.migrate()
        self.assertEqual(self.migrate(), 0)

    def test_migrate_after_init_db_skips_existing_column(self):
        database.init_db()
        self.assertEqual(self.migrate(), 3)

    def test_init_db_seeds_emails(self):
        database.init_db()
        emails = {u: e for u, e in self.raw("SELECT username, email FROM users")}
        self.assertEqual(emails["admin"], "admin@oasis.live")

    def test_add_column_filter_is_table_specific(self):
        from migrations.migrate import _skip_existing_add_columns, get_connection
        database.init_db()
        conn = get_connection(self.db_path)
        sql = ("ALTER TABLE users ADD COLUMN email TEXT;\n"
               "ALTER TABLE roles ADD COLUMN email TEXT;")
        out = _skip_existing_add_columns(conn, sql)
        conn.close()
        self.assertNotIn("TABLE users", out)
        self.assertIn("TABLE roles", out)


class AuthenticationTests(_TempDbCase):
    def setUp(self):
        super().setUp()
        self.migrate()
        import roles.accounts as accounts
        self.accounts = accounts

    def test_login_with_correct_password(self):
        user = self.accounts.authenticate_user("admin", "admin123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "admin")

    def test_wrong_password_rejected(self):
        self.assertIsNone(self.accounts.authenticate_user("admin", "nope"))

    def test_user_records_never_contain_password(self):
        self.assertNotIn("password", self.accounts.authenticate_user("admin", "admin123"))
        self.assertNotIn("password", self.accounts.get_user("admin"))
        self.assertNotIn("password", database.get_user_by_email("admin@oasis.live"))

    def test_default_password_stops_working_after_reset(self):
        self.assertTrue(database.update_user_password("admin", "N3w-Str0ng-Pass!"))
        self.assertIsNotNone(self.accounts.authenticate_user("admin", "N3w-Str0ng-Pass!"))
        self.assertIsNone(self.accounts.authenticate_user("admin", "admin123"))

    def test_deactivated_user_cannot_login(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("UPDATE users SET is_active = 0 WHERE username = 'sam'")
        self.assertIsNone(self.accounts.authenticate_user("sam", "sam123"))
        self.assertIsNone(self.accounts.get_user("sam"))

    def test_password_reset_revokes_existing_tokens(self):
        user = self.accounts.authenticate_user("alex", "alex123")
        payload = {"sub": user["username"], "username": user["username"], "role": user["role"]}
        access = security.create_access_token(payload)
        refresh = security.create_refresh_token(payload)
        self.assertIsNotNone(security.decode_token(access))
        time.sleep(1.05)  # token iat has 1-second resolution
        database.update_user_password("alex", "An0ther#Pass99")
        self.assertIsNone(security.decode_token(access))
        self.assertIsNone(security.decode_token(refresh, is_refresh=True))
        fresh = security.create_access_token(payload)
        self.assertIsNotNone(security.decode_token(fresh))


class AuthApiTests(_TempDbCase):
    def setUp(self):
        super().setUp()
        self.migrate()
        from fastapi.testclient import TestClient
        import server
        self.client = TestClient(server.app)

    def _send_reset_otp(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.client.post("/api/auth/forgot-password/send-otp",
                                    json={"email": "admin@oasis.live"})

    def _send_signup_otp(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.client.post("/api/auth/signup/send-otp", json={"email": "new@example.com"})

    def test_otp_not_returned_by_default(self):
        self.assertNotIn("dev_otp", self._send_reset_otp().json())
        self.assertNotIn("dev_otp", self._send_signup_otp().json())

    def test_otp_not_returned_when_smtp_configured_even_in_dev_mode(self):
        os.environ.update({"OASIS_DEV_MODE": "1", "OASIS_SMTP_HOST": "smtp.invalid",
                           "OASIS_SMTP_USER": "u", "OASIS_SMTP_PASS": "p"})
        import core.mailer as mailer
        self.assertFalse(mailer.should_expose_dev_otp())

    def test_otp_returned_only_in_dev_mode_without_smtp(self):
        os.environ["OASIS_DEV_MODE"] = "1"
        self.assertIn("dev_otp", self._send_reset_otp().json())

    def test_login_page_hides_default_credentials(self):
        html = self.client.get("/login").text
        self.assertNotIn("admin123", html)
        os.environ["OASIS_DEV_MODE"] = "1"
        self.assertIn("admin123", self.client.get("/login").text)

    def test_signup_response_has_no_password_hash(self):
        os.environ["OASIS_DEV_MODE"] = "1"  # needed to read the OTP in-test
        otp = self._send_signup_otp().json()["dev_otp"]
        ticket = self.client.post("/api/auth/signup/verify-otp",
                                  json={"email": "new@example.com", "otp_code": otp}).json()["verification_ticket"]
        res = self.client.post("/api/auth/signup/complete", json={
            "email": "new@example.com", "username": "newbie",
            "password": "Str0ng#Passw0rd", "confirm_password": "Str0ng#Passw0rd",
            "verification_ticket": ticket,
        })
        self.assertEqual(res.status_code, 200, res.text)
        self.assertNotIn("password", res.json()["user"])
        self.assertNotIn("pbkdf2", res.text)

    def test_login_response_has_no_password_hash(self):
        res = self.client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("pbkdf2", res.text)

    def test_smtp_environment_resolution(self):
        from core.mailer import get_smtp_config, get_app_environment

        # Test Development Environment
        os.environ["OASIS_ENV"] = "development"
        os.environ["DEV_SMTP_HOST"] = "smtp.gmail.com"
        os.environ["DEV_SMTP_USER"] = "faceoffonboarding@gmail.com"
        os.environ["DEV_SMTP_PASSWORD"] = "irlm ftie gvzs lmia"

        self.assertEqual(get_app_environment(), "development")
        dev_cfg = get_smtp_config()
        self.assertEqual(dev_cfg["user"], "faceoffonboarding@gmail.com")
        self.assertEqual(dev_cfg["password"], "irlmftiegvzslmia")
        self.assertEqual(dev_cfg["host"], "smtp.gmail.com")

        # Test Production Environment
        os.environ["OASIS_ENV"] = "production"
        os.environ["PROD_SMTP_HOST"] = "smtp.gmail.com"
        os.environ["PROD_SMTP_USER"] = "admin@foai.site"
        os.environ["PROD_SMTP_PASSWORD"] = "rsft ecax vktb owyy"

        self.assertEqual(get_app_environment(), "production")
        prod_cfg = get_smtp_config()
        self.assertEqual(prod_cfg["user"], "admin@foai.site")
        self.assertEqual(prod_cfg["password"], "rsftecaxvktbowyy")
        self.assertEqual(prod_cfg["host"], "smtp.gmail.com")


if __name__ == "__main__":
    unittest.main()
