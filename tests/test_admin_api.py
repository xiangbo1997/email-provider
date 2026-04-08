from __future__ import annotations

import os
import tempfile
import unittest

from unittest import mock


_DB_PATH = os.path.join(tempfile.gettempdir(), "email_provider_admin_api_test.db")
os.environ["MAILBOX_SERVICE_DATABASE_URL"] = f"sqlite:///{_DB_PATH}"
os.environ["EMAIL_PROVIDER_API_KEY"] = "secret-token"

from fastapi.testclient import TestClient
from sqlmodel import Session, delete

from core.base_mailbox import MailboxAccount
from main import app
from services.mailbox_service import (
    MailboxProviderConfigModel,
    MailboxSessionEventModel,
    MailboxSessionModel,
    init_mailbox_service_db,
    mailbox_service_engine,
)


class _FakeMailbox:
    def __init__(self):
        self._accounts = [{"email": "demo@example.com"}]
        self._token = "tok_demo"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email="demo@example.com", account_id="legacy")

    def get_current_ids(self, account: MailboxAccount) -> set:
        return {"m1"}

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        return "123456"


class AdminApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_mailbox_service_db()

    def setUp(self):
        with Session(mailbox_service_engine) as session:
            session.exec(delete(MailboxProviderConfigModel))
            session.exec(delete(MailboxSessionEventModel))
            session.exec(delete(MailboxSessionModel))
            session.commit()
        self.client = TestClient(app)
        self.headers = {"Authorization": "Bearer secret-token"}

    def test_provider_config_crud_and_validate(self):
        created = self.client.post(
            "/api/admin/provider-configs",
            headers=self.headers,
            json={
                "name": "applemail-prod",
                "provider": "applemail",
                "enabled": True,
                "description": "prod pool",
                "proxy": "socks5h://127.0.0.1:1080",
                "extra": {"applemail_accounts": "demo@example.com----pw----cid----rt"},
            },
        )
        self.assertEqual(created.status_code, 200)
        config_id = created.json()["id"]

        listed = self.client.get("/api/admin/provider-configs", headers=self.headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()["items"]), 1)

        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            validated = self.client.post(
                f"/api/admin/provider-configs/{config_id}/validate",
                headers=self.headers,
            )
        self.assertEqual(validated.status_code, 200)
        self.assertTrue(validated.json()["validation"]["ok"])

    def test_session_api_accepts_saved_config_id(self):
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=_FakeMailbox()):
            created = self.client.post(
                "/api/admin/provider-configs",
                headers=self.headers,
                json={
                    "name": "laoudo-prod",
                    "provider": "laoudo",
                    "enabled": True,
                    "description": "prod pool",
                    "proxy": None,
                    "extra": {"laoudo_email": "demo@example.com"},
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
        self.assertEqual(body["email"], "demo@example.com")


if __name__ == "__main__":
    unittest.main()
