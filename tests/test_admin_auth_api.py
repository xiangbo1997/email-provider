from __future__ import annotations

import unittest

from tests.fixtures import (
    TEST_ADMIN_PASSWORD,
    TEST_ADMIN_USERNAME,
    bootstrap_database,
    clean_database,
    prepare_test_environment,
)

prepare_test_environment("email_provider_admin_auth_test.db")

from fastapi.testclient import TestClient

from main import app
from services.admin_auth_service import AdminAuthEventModel, AdminLoginAttemptModel, AdminWebSessionModel
from services.mailbox_service import MailboxProviderConfigModel, MailboxSessionEventModel, MailboxSessionModel


class AdminAuthApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bootstrap_database("email_provider_admin_auth_test.db")

    def setUp(self):
        clean_database(
            [
                AdminAuthEventModel,
                AdminLoginAttemptModel,
                AdminWebSessionModel,
                MailboxProviderConfigModel,
                MailboxSessionEventModel,
                MailboxSessionModel,
            ]
        )
        self.client = TestClient(app)

    def test_login_me_logout_and_admin_page_redirects(self):
        anonymous_admin = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(anonymous_admin.status_code, 303)
        self.assertEqual(anonymous_admin.headers["location"], "/admin/login")

        login_page = self.client.get("/admin/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertIn("管理员登录", login_page.text)
        self.assertEqual(login_page.headers.get("cache-control"), "no-store")
        self.assertIn("frame-ancestors 'none'", login_page.headers.get("content-security-policy", ""))

        logged_in = self.client.post(
            "/api/admin/auth/login",
            json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD},
        )
        self.assertEqual(logged_in.status_code, 200)
        self.assertEqual(logged_in.json()["username"], TEST_ADMIN_USERNAME)
        self.assertTrue(self.client.cookies.get("email_provider_admin_session"))
        self.assertTrue(self.client.cookies.get("email_provider_admin_csrf"))

        me = self.client.get("/api/admin/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], TEST_ADMIN_USERNAME)
        self.assertEqual(me.json()["auth_mode"], "session")

        login_redirect = self.client.get("/admin/login", follow_redirects=False)
        self.assertEqual(login_redirect.status_code, 303)
        self.assertEqual(login_redirect.headers["location"], "/admin")

        logout_without_csrf = self.client.post("/api/admin/auth/logout")
        self.assertEqual(logout_without_csrf.status_code, 403)
        self.assertEqual(logout_without_csrf.json()["detail"]["code"], "CSRF_FAILED")

        logout = self.client.post(
            "/api/admin/auth/logout",
            headers={"X-CSRF-Token": self.client.cookies.get("email_provider_admin_csrf", "")},
        )
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(logout.json()["ok"], True)

        me_after_logout = self.client.get("/api/admin/auth/me")
        self.assertEqual(me_after_logout.status_code, 401)

    def test_login_rate_limit_after_repeated_failures(self):
        for attempt in range(5):
            response = self.client.post(
                "/api/admin/auth/login",
                json={"username": TEST_ADMIN_USERNAME, "password": f"wrong-{attempt}"},
            )
            self.assertEqual(response.status_code, 401)

        blocked = self.client.post(
            "/api/admin/auth/login",
            json={"username": TEST_ADMIN_USERNAME, "password": "still-wrong"},
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.json()["detail"]["code"], "RATE_LIMITED")


if __name__ == "__main__":
    unittest.main()
