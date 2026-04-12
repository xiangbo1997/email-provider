from __future__ import annotations

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from tests.test_support import DEFAULT_API_KEY, clean_all_tables, configure_test_env

_DB_PATH = os.path.join(tempfile.gettempdir(), "email_provider_api_security_test.db")
configure_test_env(_DB_PATH)

from main import app


class ApiSecurityTests(unittest.TestCase):
    def setUp(self):
        clean_all_tables()

    def test_mailbox_service_route_requires_api_key(self):
        client = TestClient(app)
        response = client.get("/api/mailbox-service/providers")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "UNAUTHORIZED")

    def test_mailbox_service_route_accepts_bearer_token(self):
        client = TestClient(app)
        response = client.get(
            "/api/mailbox-service/providers",
            headers={"Authorization": f"Bearer {DEFAULT_API_KEY}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_healthz_remains_public(self):
        client = TestClient(app)
        response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

    def test_admin_page_redirects_to_login_when_not_authenticated(self):
        client = TestClient(app, follow_redirects=False)
        response = client.get("/admin")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/admin/login")

        login_page = client.get("/admin/login")
        self.assertEqual(login_page.status_code, 200)
        self.assertIn("管理员登录", login_page.text)

    def test_auth_disabled_does_not_bypass_admin_routes(self):
        client = TestClient(app)
        old_disabled = os.environ.get("EMAIL_PROVIDER_AUTH_DISABLED")
        os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = "1"
        try:
            mailbox_resp = client.get("/api/mailbox-service/providers")
            self.assertEqual(mailbox_resp.status_code, 200)

            admin_resp = client.get("/api/admin/provider-catalog")
            self.assertEqual(admin_resp.status_code, 401)
        finally:
            if old_disabled is None:
                os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
            else:
                os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = old_disabled


if __name__ == "__main__":
    unittest.main()
