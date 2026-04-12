from __future__ import annotations

import os
import tempfile
import unittest

from unittest import mock

from fastapi.testclient import TestClient

from tests.test_support import DEFAULT_API_KEY, clean_all_tables, configure_test_env

_DB_PATH = os.path.join(tempfile.gettempdir(), "email_provider_admin_api_test.db")
configure_test_env(_DB_PATH)

from core.base_mailbox import MailboxAccount
from main import app


class _FakeMailbox:
    def __init__(self):
        self._accounts = [{"email": "demo@example.com"}]
        self._token = "tok_demo"
        self._order_no = "order-001"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email="demo@example.com", account_id="legacy", extra={"mailbox_token": "tok_demo"})

    def get_current_ids(self, account: MailboxAccount) -> set:
        return {"m1"}

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        return "123456"


class AdminApiTests(unittest.TestCase):
    def setUp(self):
        clean_all_tables()
        self.client = TestClient(app)
        self.headers = {"Authorization": f"Bearer {DEFAULT_API_KEY}"}

    def test_provider_config_crud_list_detail_and_validate(self):
        created = self.client.post(
            "/api/admin/provider-configs",
            headers=self.headers,
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
        self.assertIn("extra", created.json())

        listed = self.client.get("/api/admin/provider-configs", headers=self.headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["items"]), 1)
        item = listed.json()["items"][0]
        self.assertEqual(item["id"], config_id)
        self.assertTrue(item["proxy_configured"])
        self.assertNotIn("proxy", item)
        self.assertNotIn("extra", item)
        self.assertIn("***@127.0.0.1:1080", item["proxy_masked"])

        filtered = self.client.get(
            "/api/admin/provider-configs",
            headers=self.headers,
            params={"q": "prod", "provider": "applemail", "enabled": "true"},
        )
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(len(filtered.json()["items"]), 1)

        detail = self.client.get(f"/api/admin/provider-configs/{config_id}", headers=self.headers)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["proxy"], "socks5h://user:pass@127.0.0.1:1080")
        self.assertEqual(detail.json()["extra"]["applemail_accounts"], "demo@example.com----pw----cid----rt")

        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            validated = self.client.post(
                f"/api/admin/provider-configs/{config_id}/validate",
                headers=self.headers,
            )
        self.assertEqual(validated.status_code, 200)
        self.assertTrue(validated.json()["validation"]["ok"])

        updated = self.client.put(
            f"/api/admin/provider-configs/{config_id}",
            headers=self.headers,
            json={
                "name": "applemail-stage",
                "provider": "applemail",
                "enabled": False,
                "description": "stage pool",
                "proxy": None,
                "extra": {"applemail_accounts": "other@example.com----pw----cid----rt"},
            },
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "applemail-stage")
        self.assertFalse(updated.json()["enabled"])
        self.assertEqual(updated.json()["proxy"], "")

        deleted = self.client.delete(f"/api/admin/provider-configs/{config_id}", headers=self.headers)
        self.assertEqual(deleted.status_code, 200)
        missing = self.client.get(f"/api/admin/provider-configs/{config_id}", headers=self.headers)
        self.assertEqual(missing.status_code, 404)

    def test_session_api_accepts_saved_config_id_and_recent_sessions_redacts(self):
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            created = self.client.post(
                "/api/admin/provider-configs",
                headers=self.headers,
                json={
                    "name": "laoudo-prod",
                    "provider": "laoudo",
                    "enabled": True,
                    "description": "prod pool",
                    "proxy": "socks5h://127.0.0.1:1080",
                    "extra": {"laoudo_email": "demo@example.com", "laoudo_auth": "secret-auth"},
                },
            )
            config_id = created.json()["id"]

            session_resp = self.client.post(
                "/api/mailbox-service/sessions",
                headers=self.headers,
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
        self.assertEqual(body["email"], "demo@example.com")

        recent = self.client.get(
            "/api/admin/recent-sessions",
            headers=self.headers,
            params={"provider": "laoudo", "state": "leased"},
        )
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.json()["items"]), 1)
        item = recent.json()["items"][0]
        self.assertEqual(item["provider"], "laoudo")
        self.assertEqual(item["state"], "leased")
        self.assertIn("provider_meta", item)
        self.assertEqual(item["provider_meta"]["mailbox_token"], "***")
        self.assertIn("proxy_masked", item)


if __name__ == "__main__":
    unittest.main()
