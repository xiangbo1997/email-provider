from __future__ import annotations

import json
import unittest

from unittest import mock

from tests.fixtures import (
    TEST_ADMIN_PASSWORD,
    TEST_ADMIN_USERNAME,
    TEST_API_KEY,
    bootstrap_database,
    clean_database,
    prepare_test_environment,
)

prepare_test_environment("email_provider_admin_api_test.db")

from fastapi.testclient import TestClient
from sqlmodel import Session

from main import app
from services.admin_auth_service import AdminAuthEventModel, AdminLoginAttemptModel, AdminWebSessionModel
from services.crypto_utils import hash_token
from services.database import get_mailbox_service_engine
from services.mailbox_service import (
    MailboxProviderConfigModel,
    MailboxSessionEventModel,
    MailboxSessionModel,
)
from core.base_mailbox import MailboxAccount


class _FakeMailbox:
    def __init__(self, *, code: str = "123456"):
        self._code = code
        self._accounts = [{"email": "demo@example.com"}]
        self._token = "tok_demo"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email="demo@example.com", account_id="legacy")

    def get_current_ids(self, account: MailboxAccount) -> set[str]:
        return {"m1"}

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        return self._code


class AdminApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bootstrap_database("email_provider_admin_api_test.db")

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
        self.api_key_headers = {"Authorization": f"Bearer {TEST_API_KEY}"}

    def _login_headers(self) -> tuple[TestClient, dict[str, str]]:
        client = TestClient(app)
        response = client.post(
            "/api/admin/auth/login",
            json={"username": TEST_ADMIN_USERNAME, "password": TEST_ADMIN_PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        csrf = client.cookies.get("email_provider_admin_csrf")
        self.assertTrue(csrf)
        return client, {"X-CSRF-Token": csrf}

    def test_provider_config_crud_validate_summary_and_storage_security(self):
        client, csrf_headers = self._login_headers()

        created = client.post(
            "/api/admin/provider-configs",
            headers=csrf_headers,
            json={
                "name": "applemail-prod",
                "provider": "applemail",
                "enabled": True,
                "description": "prod pool",
                "proxy": "socks5h://user:pass@127.0.0.1:1080",
                "extra": {"applemail_accounts": "demo@example.com----pw----cid----rt"},
            },
        )
        self.assertEqual(created.status_code, 200)
        config_id = created.json()["id"]
        self.assertEqual(created.json()["proxy"], "socks5h://user:pass@127.0.0.1:1080")
        self.assertIn("applemail_accounts", created.json()["extra"])

        listed = client.get("/api/admin/provider-configs")
        self.assertEqual(listed.status_code, 200)
        item = listed.json()["items"][0]
        self.assertEqual(item["id"], config_id)
        self.assertTrue(item["proxy_configured"])
        self.assertIn("127.0.0.1", item["proxy_masked"])
        self.assertNotIn("proxy", item)
        self.assertNotIn("extra", item)

        detail = client.get(f"/api/admin/provider-configs/{config_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["proxy"], "socks5h://user:pass@127.0.0.1:1080")
        self.assertEqual(detail.json()["extra"]["applemail_accounts"], "demo@example.com----pw----cid----rt")

        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            validated = client.post(
                f"/api/admin/provider-configs/{config_id}/validate",
                headers=csrf_headers,
            )
        self.assertEqual(validated.status_code, 200)
        self.assertTrue(validated.json()["validation"]["ok"])

        with Session(get_mailbox_service_engine()) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            self.assertIsNotNone(model)
            self.assertNotEqual(model.proxy, "socks5h://user:pass@127.0.0.1:1080")
            self.assertNotEqual(model.extra_json, json.dumps({"applemail_accounts": "demo@example.com----pw----cid----rt"}, ensure_ascii=False))
            self.assertNotIn("pw", model.extra_json)
            self.assertNotIn("user:pass", model.proxy)

    def test_admin_api_key_fallback_and_mailbox_session_storage_security(self):
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            created = self.client.post(
                "/api/admin/provider-configs",
                headers=self.api_key_headers,
                json={
                    "name": "laoudo-prod",
                    "provider": "laoudo",
                    "enabled": True,
                    "description": "prod pool",
                    "proxy": None,
                    "extra": {"laoudo_email": "demo@example.com", "laoudo_auth": "token-123"},
                },
            )
            self.assertEqual(created.status_code, 200)
            config_id = created.json()["id"]

            session_resp = self.client.post(
                "/api/mailbox-service/sessions",
                headers=self.api_key_headers,
                json={
                    "config_id": config_id,
                    "purpose": "register",
                    "lease_seconds": 120,
                },
            )

        self.assertEqual(session_resp.status_code, 200)
        body = session_resp.json()
        self.assertEqual(body["provider"], "laoudo")
        self.assertEqual(body["provider_config"]["id"], config_id)
        self.assertNotIn("extra", body["provider_config"])
        self.assertNotIn("proxy", body["provider_config"])

        with Session(get_mailbox_service_engine()) as session:
            model = session.get(MailboxSessionModel, body["session_id"])
            self.assertIsNotNone(model)
            self.assertEqual(model.lease_token, hash_token(body["lease_token"]))
            self.assertNotEqual(model.lease_token, body["lease_token"])
            self.assertNotIn(body["lease_token"], model.lease_token)
            self.assertNotIn("token-123", model.config_json)
            self.assertNotIn("tok_demo", model.provider_meta_json)

    def test_admin_write_requires_csrf_for_session_auth(self):
        client, _csrf_headers = self._login_headers()
        response = client.post(
            "/api/admin/provider-configs",
            json={
                "name": "bad-create",
                "provider": "laoudo",
                "enabled": True,
                "description": "missing csrf",
                "proxy": None,
                "extra": {},
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["code"], "CSRF_FAILED")


if __name__ == "__main__":
    unittest.main()
