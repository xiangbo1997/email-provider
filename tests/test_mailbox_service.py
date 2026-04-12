from __future__ import annotations

import os
import tempfile
import unittest

from unittest import mock

from sqlmodel import Session, select

from tests.test_support import clean_all_tables, configure_test_env, engine

_DB_PATH = os.path.join(tempfile.gettempdir(), "email_provider_mailbox_service_test.db")
configure_test_env(_DB_PATH)

from core.base_mailbox import MailboxAccount, MailboxServiceBackedMailbox
from services.mailbox_service import (
    MailboxProviderConfigModel,
    MailboxSessionModel,
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
            extra={"source": "fake", "mailbox_token": "runtime-token"},
        )

    def get_current_ids(self, account: MailboxAccount) -> set:
        return {"m1", "m2"}

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        if self._error:
            raise self._error
        return self._code

    def remove_used_account(self):
        self._removed = True


class MailboxServiceTests(unittest.TestCase):
    def setUp(self):
        clean_all_tables()

    def test_service_session_lifecycle_and_cleanup(self):
        fake_mailbox = _FakeMailbox()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            lease = mailbox_service.acquire_session(
                provider="laoudo",
                extra={"laoudo_auth": "token-123"},
                proxy="socks5h://user:pass@127.0.0.1:1080",
                purpose="register",
            )
            self.assertEqual(lease.email, "demo@example.com")
            self.assertEqual(set(lease.before_ids), {"m1", "m2"})
            self.assertEqual(lease.provider_meta["mailbox_order_no"], "ord_demo")

            result = mailbox_service.poll_code(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                timeout_seconds=10,
                before_ids=set(lease.before_ids),
            )
            self.assertEqual(result.status, "ready")
            self.assertEqual(result.code, "123456")

            mailbox_service.complete_session(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                result="success",
            )
            self.assertTrue(fake_mailbox._removed)

    def test_sensitive_fields_are_encrypted_and_lease_token_is_hashed(self):
        fake_mailbox = _FakeMailbox()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            saved = mailbox_service.create_provider_config(
                name="demo-laoudo",
                provider="laoudo",
                extra={"laoudo_auth": "token-123", "laoudo_email": "demo@example.com"},
                proxy="socks5h://user:pass@127.0.0.1:1080",
                description="demo",
            )
            lease = mailbox_service.acquire_session(
                provider="laoudo",
                extra={"laoudo_auth": "token-123"},
                proxy="socks5h://user:pass@127.0.0.1:1080",
                purpose="register",
            )

        with Session(engine()) as session:
            config_model = session.exec(select(MailboxProviderConfigModel).where(MailboxProviderConfigModel.id == saved["id"])).one()
            self.assertNotIn("token-123", config_model.extra_json)
            self.assertNotIn("user:pass", config_model.proxy)

            session_model = session.get(MailboxSessionModel, lease.session_id)
            self.assertEqual(session_model.lease_token, "")
            self.assertNotEqual(session_model.lease_token_hash, lease.lease_token)
            self.assertEqual(len(session_model.lease_token_hash), 64)
            self.assertNotIn("token-123", session_model.config_json)
            self.assertNotIn("runtime-token", session_model.provider_meta_json)
            self.assertNotIn("user:pass", session_model.proxy)

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
                extra={"laoudo_email": "demo@example.com", "laoudo_auth": "token-123"},
                proxy="socks5h://127.0.0.1:1080",
                description="demo",
            )
            runtime = mailbox_service.resolve_provider_request(config_id=saved["id"])
            self.assertEqual(runtime["provider"], "laoudo")
            self.assertEqual(runtime["proxy"], "socks5h://127.0.0.1:1080")
            self.assertEqual(runtime["config"]["name"], "demo-laoudo")
            self.assertNotIn("extra", runtime["config"])

            lease = mailbox_service.acquire_session(
                provider=runtime["provider"],
                extra=runtime["extra"],
                proxy=runtime["proxy"],
                purpose="register",
            )
            self.assertEqual(lease.email, "demo@example.com")

    def test_legacy_plaintext_lease_token_still_works(self):
        fake_mailbox = _FakeMailbox(code="777777")
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            lease = mailbox_service.acquire_session(provider="laoudo", extra={}, proxy=None, purpose="register")
            with Session(engine()) as session:
                model = session.get(MailboxSessionModel, lease.session_id)
                model.lease_token = lease.lease_token
                model.lease_token_hash = ""
                session.add(model)
                session.commit()

            result = mailbox_service.poll_code(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                timeout_seconds=10,
                before_ids=set(lease.before_ids),
            )
            self.assertEqual(result.status, "ready")
            self.assertEqual(result.code, "777777")


if __name__ == "__main__":
    unittest.main()
