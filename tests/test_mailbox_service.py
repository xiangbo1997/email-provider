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


class _FakeDynamicAppleMailBox(_FakeMailbox):
    def __init__(self, *, code: str = "123456"):
        super().__init__(code=code)
        self._accounts = []
        self._selected = {}
        self._clear_mailbox = mock.Mock()

    def wait_for_code(self, account: MailboxAccount, **kwargs) -> str:
        selected = next(
            (item for item in self._accounts if item.get("email", "").lower() == account.email.lower()),
            self._selected or None,
        )
        if not selected:
            raise RuntimeError(f"未找到 {account.email} 的 AppleMail 账号配置")
        return self._code


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

    def test_provider_catalog_exposes_session_metadata(self):
        catalog = {item["name"]: item for item in mailbox_service.provider_catalog()}

        self.assertEqual(catalog["applemail"]["default_session_mode"], "managed")
        self.assertIn("credentialed", catalog["applemail"]["supported_session_modes"])
        self.assertIn(
            "existing_account.credentials.refresh_token",
            catalog["applemail"]["required_fields_by_mode"]["credentialed"],
        )

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

    def test_known_applemail_account_extra_can_bootstrap_runtime_context(self):
        fake_mailbox = _FakeMailbox(code="246810")
        fake_mailbox._accounts = []
        fake_mailbox._selected = {}
        fake_mailbox._clear_mailbox = mock.Mock()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            lease = mailbox_service.acquire_session(
                provider="applemail",
                session_mode="credentialed",
                extra={},
                proxy=None,
                purpose="register",
                account_override=MailboxAccount(
                    email="known@example.com",
                    account_id="",
                    extra={
                        "client_id": "cid-known",
                        "refresh_token": "rt-known",
                        "preserve_existing_mail": True,
                    },
                ),
            )

        self.assertEqual(lease.email, "known@example.com")
        self.assertEqual(lease.session_mode, "credentialed")
        self.assertEqual(fake_mailbox._selected["email"], "known@example.com")
        self.assertEqual(fake_mailbox._selected["client_id"], "cid-known")
        self.assertEqual(fake_mailbox._selected["refresh_token"], "rt-known")
        self.assertTrue(any(item["email"] == "known@example.com" for item in fake_mailbox._accounts))
        fake_mailbox._clear_mailbox.assert_not_called()
        with Session(engine()) as session:
            model = session.get(MailboxSessionModel, lease.session_id)
            self.assertEqual(model.session_mode, "credentialed")

    def test_credentialed_mode_requires_existing_account(self):
        fake_mailbox = _FakeMailbox()
        with mock.patch("core.base_mailbox.create_local_mailbox", return_value=fake_mailbox):
            with self.assertRaisesRegex(Exception, "existing_account"):
                mailbox_service.acquire_session(
                    provider="applemail",
                    session_mode="credentialed",
                    extra={},
                    proxy=None,
                    purpose="register",
                )

    def test_credentialed_poll_code_rehydrates_dynamic_applemail_account(self):
        acquire_mailbox = _FakeDynamicAppleMailBox(code="246810")
        poll_mailbox = _FakeDynamicAppleMailBox(code="246810")
        with mock.patch(
            "core.base_mailbox.create_local_mailbox",
            side_effect=[acquire_mailbox, poll_mailbox],
        ):
            lease = mailbox_service.acquire_session(
                provider="applemail",
                session_mode="credentialed",
                extra={},
                proxy=None,
                purpose="register",
                account_override=MailboxAccount(
                    email="known@example.com",
                    account_id="",
                    extra={
                        "client_id": "cid-known",
                        "refresh_token": "rt-known",
                        "preserve_existing_mail": True,
                    },
                ),
            )
            result = mailbox_service.poll_code(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                timeout_seconds=10,
                before_ids=set(lease.before_ids),
            )

        self.assertEqual(result.status, "ready")
        self.assertEqual(result.code, "246810")
        self.assertEqual(poll_mailbox._selected["email"], "known@example.com")
        self.assertTrue(any(item["email"] == "known@example.com" for item in poll_mailbox._accounts))


class ExistingAccountFieldPresentTests(unittest.TestCase):
    """``MailboxService._existing_account_field_present`` dotted-path 解析行为。

    背景：``api/mailbox_service.py:_build_account_override_from_existing_account``
    会把 ``ExistingAccount.credentials.X`` 摊平到 ``MailboxAccount.extra["X"]``。
    PROVIDER_SESSION_METADATA 里 applemail credentialed 模式声明的字段路径却是
    嵌套形态 ``existing_account.credentials.client_id``，所以解析逻辑必须能
    跨这层模型不一致。
    """

    def setUp(self):
        # 直接调用静态方法，无需 DB / 网络
        self._fn = mailbox_service._existing_account_field_present

    def test_email_attribute_path_present(self):
        # case 3：existing_account.email 直接挂在 MailboxAccount 上 → 走属性路径
        ao = MailboxAccount(email="x@y.c", account_id="", extra={})
        self.assertTrue(self._fn(ao, "existing_account.email"))

    def test_email_attribute_path_empty(self):
        ao = MailboxAccount(email="", account_id="", extra={})
        self.assertFalse(self._fn(ao, "existing_account.email"))

    def test_account_id_attribute_empty_extra_fallback(self):
        # case 4：account_id 属性为空时走 extra[head] fallback（保持原有 fallback 路径）
        ao = MailboxAccount(email="x@y.c", account_id="", extra={"account_id": "xyz"})
        self.assertTrue(self._fn(ao, "existing_account.account_id"))

    def test_credentials_flat_extra_present(self):
        # case 1：credentials.client_id 摊平到 extra["client_id"] → 第 3 层 fallback 命中
        ao = MailboxAccount(
            email="x@y.c",
            account_id="",
            extra={"client_id": "abc", "refresh_token": "rt"},
        )
        self.assertTrue(self._fn(ao, "existing_account.credentials.client_id"))
        self.assertTrue(self._fn(ao, "existing_account.credentials.refresh_token"))

    def test_credentials_flat_extra_empty(self):
        # case 2：摊平 key 存在但值为空 → False
        ao = MailboxAccount(
            email="x@y.c",
            account_id="",
            extra={"client_id": "", "refresh_token": ""},
        )
        self.assertFalse(self._fn(ao, "existing_account.credentials.client_id"))
        self.assertFalse(self._fn(ao, "existing_account.credentials.refresh_token"))

    def test_credentials_flat_extra_missing_key(self):
        # case 2 变体：extra 完全没有摊平 key → False（不会与其他字段误匹配）
        ao = MailboxAccount(email="x@y.c", account_id="", extra={"unrelated": "v"})
        self.assertFalse(self._fn(ao, "existing_account.credentials.client_id"))

    def test_nested_extra_dict_still_works(self):
        # 第 2 层 fallback：head 直接是 extra 顶层 dict 形态（旧约定，保持向后兼容）
        ao = MailboxAccount(
            email="x@y.c",
            account_id="",
            extra={"credentials": {"client_id": "nested-abc"}},
        )
        self.assertTrue(self._fn(ao, "existing_account.credentials.client_id"))

    def test_account_override_none_returns_false(self):
        self.assertFalse(self._fn(None, "existing_account.email"))


if __name__ == "__main__":
    unittest.main()
