from __future__ import annotations

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from tests.test_support import (
    DEFAULT_ADMIN_PASSWORD,
    DEFAULT_ADMIN_USERNAME,
    DEFAULT_API_KEY,
    clean_all_tables,
    configure_test_env,
)

_DB_PATH = os.path.join(tempfile.gettempdir(), "email_provider_admin_auth_api_test.db")
configure_test_env(_DB_PATH)

from main import app
from services.admin_auth_service import admin_auth_service


class AdminAuthApiTests(unittest.TestCase):
    def setUp(self):
        clean_all_tables()
        self.client = TestClient(app)

    def test_login_me_csrf_logout_flow(self):
        login = self.client.post(
            "/api/admin/auth/login",
            json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["username"], DEFAULT_ADMIN_USERNAME)
        self.assertIn(admin_auth_service.SESSION_COOKIE_NAME, self.client.cookies)
        self.assertIn(admin_auth_service.CSRF_COOKIE_NAME, self.client.cookies)

        me = self.client.get("/api/admin/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["auth_mode"], "session")
        self.assertEqual(me.json()["username"], DEFAULT_ADMIN_USERNAME)

        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn("邮箱服务管理台", admin_page.text)

        no_csrf = self.client.post(
            "/api/admin/provider-configs",
            json={"name": "x", "provider": "laoudo", "enabled": True, "description": "", "proxy": None, "extra": {}},
        )
        self.assertEqual(no_csrf.status_code, 403)

        csrf_token = self.client.cookies.get(admin_auth_service.CSRF_COOKIE_NAME)
        created = self.client.post(
            "/api/admin/provider-configs",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "name": "session-created",
                "provider": "laoudo",
                "enabled": True,
                "description": "from-session",
                "proxy": None,
                "extra": {"laoudo_email": "demo@example.com"},
            },
        )
        self.assertEqual(created.status_code, 200)

        logout = self.client.post(
            "/api/admin/auth/logout",
            headers={"X-CSRF-Token": csrf_token},
        )
        self.assertEqual(logout.status_code, 200)

        me_after = self.client.get("/api/admin/auth/me")
        self.assertEqual(me_after.status_code, 401)

        admin_after = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(admin_after.status_code, 303)
        self.assertEqual(admin_after.headers["location"], "/admin/login")

    def test_invalid_credentials_are_rejected(self):
        response = self.client.post(
            "/api/admin/auth/login",
            json={"username": DEFAULT_ADMIN_USERNAME, "password": "wrong-password"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_ADMIN_CREDENTIALS")

    def test_admin_api_key_fallback_still_works(self):
        headers = {"Authorization": f"Bearer {DEFAULT_API_KEY}"}
        catalog = self.client.get("/api/admin/provider-catalog", headers=headers)
        self.assertEqual(catalog.status_code, 200)
        self.assertGreaterEqual(len(catalog.json()["providers"]), 1)

        created = self.client.post(
            "/api/admin/provider-configs",
            headers=headers,
            json={
                "name": "api-key-created",
                "provider": "laoudo",
                "enabled": True,
                "description": "api-key",
                "proxy": None,
                "extra": {"laoudo_email": "demo@example.com"},
            },
        )
        self.assertEqual(created.status_code, 200)

        me = self.client.get("/api/admin/auth/me", headers=headers)
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["auth_mode"], "api_key")


if __name__ == "__main__":
    unittest.main()
