from __future__ import annotations

import os
import unittest

from fastapi.testclient import TestClient

from main import app


class ApiSecurityTests(unittest.TestCase):
    def test_protected_route_requires_api_key(self):
        old_api_key = os.environ.get("EMAIL_PROVIDER_API_KEY")
        old_disabled = os.environ.get("EMAIL_PROVIDER_AUTH_DISABLED")
        os.environ["EMAIL_PROVIDER_API_KEY"] = "secret-token"
        os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
        try:
            client = TestClient(app)
            response = client.get("/api/mailbox-service/providers")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()["detail"]["code"], "UNAUTHORIZED")
        finally:
            if old_api_key is None:
                os.environ.pop("EMAIL_PROVIDER_API_KEY", None)
            else:
                os.environ["EMAIL_PROVIDER_API_KEY"] = old_api_key
            if old_disabled is None:
                os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
            else:
                os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = old_disabled

    def test_protected_route_accepts_bearer_token(self):
        old_api_key = os.environ.get("EMAIL_PROVIDER_API_KEY")
        old_disabled = os.environ.get("EMAIL_PROVIDER_AUTH_DISABLED")
        os.environ["EMAIL_PROVIDER_API_KEY"] = "secret-token"
        os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
        try:
            client = TestClient(app)
            response = client.get(
                "/api/mailbox-service/providers",
                headers={"Authorization": "Bearer secret-token"},
            )
            self.assertEqual(response.status_code, 200)
        finally:
            if old_api_key is None:
                os.environ.pop("EMAIL_PROVIDER_API_KEY", None)
            else:
                os.environ["EMAIL_PROVIDER_API_KEY"] = old_api_key
            if old_disabled is None:
                os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
            else:
                os.environ["EMAIL_PROVIDER_AUTH_DISABLED"] = old_disabled

    def test_healthz_remains_public(self):
        client = TestClient(app)
        response = client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
