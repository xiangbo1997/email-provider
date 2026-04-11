from __future__ import annotations

import json
import unittest

from datetime import timedelta
from unittest import mock

from tests.fixtures import bootstrap_database, clean_database, prepare_test_environment

prepare_test_environment("any_auto_register_mailbox_service_test.db")

from sqlmodel import Session

from core.base_mailbox import MailboxAccount, MailboxServiceBackedMailbox
from services.database import get_mailbox_service_engine
from services.mailbox_service import (
    MailboxProviderConfigModel,
    MailboxSessionEventModel,
    MailboxSessionModel,
    MailboxService,
    mailbox_service,
)


class _FakeMailbox:
    def __init__(self, *, code: str = "123456", error: Exception | None = None):
        self._code = code
        self._error = error
        self._removed = False
        self._accounts = [{"email": "demo@example.com"}]
        self._selected = {}
        self._token = "tok_demo"
        self._order_no = "ord_demo"

    def get_email(self) -> MailboxAccount:
        return MailboxAccount(
            email="demo@example.com",
            account_id="legacy-account-id",
            extra={"source": "fake"},
        )

    def get_current_ids(self, account: MailboxAccount) -> set[str]:
        return {"m1", "m2"}

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        if self._error:
            raise self._error
        return self._code

    def remove_used_account(self):
        self._removed = True


class MailboxServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bootstrap_database("any_auto_register_mailbox_service_test.db")

    def setUp(self):
        clean_database(
            [
                MailboxProviderConfigModel,
                MailboxSessionEventModel,
                MailboxSessionModel,
            ]
        )

    def test_service_session_lifecycle_and_cleanup_uses_hashed_and_encrypted_storage(self):
        fake_mailbox = _FakeMailbox()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            lease = mailbox_service.acquire_session(
                provider="laoudo",
                extra={"laoudo_auth": "secret-auth"},
                proxy="socks5h://127.0.0.1:1080",
                purpose="register",
            )
            self.assertEqual(lease.email, "demo@example.com")
            self.assertEqual(set(lease.before_ids), {"m1", "m2"})
            self.assertEqual(lease.provider_meta["mailbox_token"], "tok_demo")

            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxSessionModel, lease.session_id)
                self.assertIsNotNone(model)
                self.assertNotEqual(model.lease_token, lease.lease_token)
                self.assertNotIn("secret-auth", model.config_json)
                self.assertNotIn("tok_demo", model.provider_meta_json)
                self.assertNotIn("127.0.0.1:1080", model.proxy)

            result = mailbox_service.poll_code(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                timeout_seconds=10,
                before_ids=set(lease.before_ids),
            )
            self.assertEqual(result.status, "ready")
            self.assertEqual(result.code, "123456")

            completed = mailbox_service.complete_session(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                result="success",
            )
            self.assertTrue(fake_mailbox._removed)
            self.assertEqual(completed.lease_token, lease.lease_token)

    def test_service_backed_mailbox_keeps_legacy_call_shape(self):
        fake_mailbox = _FakeMailbox(code="654321")
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            mailbox = MailboxServiceBackedMailbox(provider="laoudo", extra={}, proxy=None)
            account = mailbox.get_email()
            before_ids = mailbox.get_current_ids(account)
            code = mailbox.wait_for_code(account, timeout=10, before_ids=before_ids)
            mailbox.complete_success()

            self.assertEqual(account.email, "demo@example.com")
            self.assertEqual(code, "654321")
            self.assertEqual(before_ids, {"m1", "m2"})
            self.assertTrue(fake_mailbox._removed)

    def test_invalid_grant_maps_to_runtime_error_in_adapter(self):
        fake_mailbox = _FakeMailbox(error=RuntimeError("invalid_grant"))
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            mailbox = MailboxServiceBackedMailbox(provider="laoudo", extra={}, proxy=None)
            account = mailbox.get_email()
            with self.assertRaises(RuntimeError):
                mailbox.wait_for_code(account, timeout=10, before_ids=set())

    def test_saved_provider_config_can_drive_session_creation(self):
        fake_mailbox = _FakeMailbox()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            saved = mailbox_service.create_provider_config(
                name="demo-laoudo",
                provider="laoudo",
                extra={"laoudo_email": "demo@example.com", "laoudo_auth": "secret-auth"},
                proxy="socks5h://127.0.0.1:1080",
                description="demo",
            )
            runtime = mailbox_service.resolve_provider_request(config_id=saved["id"])
            self.assertEqual(runtime["provider"], "laoudo")
            self.assertEqual(runtime["proxy"], "socks5h://127.0.0.1:1080")
            self.assertEqual(runtime["extra"]["laoudo_auth"], "secret-auth")
            self.assertEqual(runtime["config"]["name"], "demo-laoudo")
            self.assertNotIn("extra", runtime["config"])
            self.assertNotIn("proxy", runtime["config"])

            lease = mailbox_service.acquire_session(
                provider=runtime["provider"],
                extra=runtime["extra"],
                proxy=runtime["proxy"],
                purpose="register",
            )
            self.assertEqual(lease.email, "demo@example.com")

    def test_plaintext_legacy_rows_remain_readable(self):
        service = MailboxService()
        with Session(get_mailbox_service_engine()) as session:
            config = MailboxProviderConfigModel(
                name="legacy-config",
                provider="laoudo",
                enabled=True,
                description="legacy",
                proxy="socks5h://127.0.0.1:1080",
                extra_json=json.dumps({"laoudo_email": "demo@example.com", "laoudo_auth": "legacy-auth"}, ensure_ascii=False),
            )
            session.add(config)
            session.commit()
            session.refresh(config)
            config_id = int(config.id)

            session_model = MailboxSessionModel(
                session_id="legacy-session",
                lease_token="legacy-lease-token",
                provider="laoudo",
                email="demo@example.com",
                account_id="legacy-id",
                purpose="legacy",
                state="leased",
                proxy="socks5h://127.0.0.1:1080",
                config_json=json.dumps({"laoudo_email": "demo@example.com"}, ensure_ascii=False),
                account_extra_json=json.dumps({"source": "legacy"}, ensure_ascii=False),
                before_ids_json=json.dumps(["m1"]),
                provider_meta_json=json.dumps({"mailbox_token": "tok-legacy"}, ensure_ascii=False),
            )
            session_model.expires_at = session_model.created_at + timedelta(minutes=15)
            session.add(session_model)
            session.commit()

        detail = service.get_provider_config(config_id)
        self.assertEqual(detail["proxy"], "socks5h://127.0.0.1:1080")
        self.assertEqual(detail["extra"]["laoudo_auth"], "legacy-auth")

        model = service.get_session_model("legacy-session", "legacy-lease-token")
        self.assertEqual(model.session_id, "legacy-session")
        lease = service.get_session("legacy-session")
        self.assertEqual(lease.provider_meta["mailbox_token"], "tok-legacy")


if __name__ == "__main__":
    unittest.main()
