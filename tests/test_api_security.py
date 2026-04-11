from __future__ import annotations

import os
import unittest

from tests.fixtures import TEST_API_KEY, bootstrap_database, clean_database, prepare_test_environment

prepare_test_environment("email_provider_api_security_test.db")

from fastapi.testclient import TestClient

from main import app
from services.admin_auth_service import AdminAuthEventModel, AdminLoginAttemptModel, AdminWebSessionModel
from services.mailbox_service import MailboxProviderConfigModel, MailboxSessionEventModel, MailboxSessionModel


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bootstrap_database("email_provider_api_security_test.db")

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

    def test_protected_route_requires_api_key(self):
        old_disabled = os.environ.get("EMAIL_PROVIDER_AUTH_DISABLED")
        os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
        try:
            response = self.client.get("/api/mailbox-service/providers")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"]["code"], "UNAUTHORIZED")
        finally:
            if old_disabled is None:
                os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
            else:
                os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = old_disabled

    def test_protected_route_accepts_bearer_token(self):
        response = self.client.get(
            "/api/mailbox-service/providers",
            headers={"Authorization": f"Bearer {TEST_API_KEY}"},
        )
        self.assertEqual(response.status_code, 200)

    def test_healthz_remains_public(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

    def test_admin_routes_do_not_bypass_login_when_mailbox_auth_disabled(self):
        old_disabled = os.environ.get("EMAIL_PROVIDER_AUTH_DISABLED")
        os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = "1"
        try:
            unauthorized = self.client.get("/api/admin/provider-catalog")
            self.assertEqual(unauthorized.status_code, 401)
            self.assertEqual(unauthorized.json()["detail"]["code"], "UNAUTHORIZED")

            authorized = self.client.get(
                "/api/admin/provider-catalog",
                headers={"Authorization": f"Bearer {TEST_API_KEY}"},
            )
            self.assertEqual(authorized.status_code, 200)
        finally:
            if old_disabled is None:
                os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
            else:
                os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = old_disabled


if __name__ == "__main__":
    unittest.main()
