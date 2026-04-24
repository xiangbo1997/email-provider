import unittest
from unittest import mock

from core.base_mailbox import AppleMailMailbox, MailboxAccount


class AppleMailMailboxTests(unittest.TestCase):
    def _build_mailbox(self):
        mailbox = AppleMailMailbox.__new__(AppleMailMailbox)
        mailbox._proxy = None
        mailbox._accounts = [
            {
                "email": "demo@example.com",
                "password": "pw",
                "client_id": "cid",
                "refresh_token": "rt",
                "raw": "demo@example.com----pw----cid----rt",
            }
        ]
        mailbox._selected = mailbox._accounts[0]
        mailbox._log_fn = None
        return mailbox

    def test_fetch_latest_supports_dict_payload(self):
        mailbox = self._build_mailbox()

        class _Resp:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "code": 200,
                    "success": True,
                    "data": {
                        "send": "noreply@tm.openai.com",
                        "subject": "Your ChatGPT code is 584863",
                        "text": "Your ChatGPT code is 584863",
                        "date": "2026-04-03T04:43:54Z",
                    },
                }

        session = mock.Mock()
        session.get.return_value = _Resp()
        mailbox._session = mock.Mock(return_value=session)

        msg = mailbox._fetch_latest(mailbox._accounts[0], "INBOX")

        self.assertEqual(msg["subject"], "Your ChatGPT code is 584863")
        self.assertEqual(mailbox._safe_extract(msg.get("text") or msg.get("subject")), "584863")

    def test_wait_for_code_supports_list_payload_and_picks_latest_mail(self):
        mailbox = self._build_mailbox()

        class _Resp:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "code": 200,
                    "success": True,
                    "data": [
                        {
                            "send": "noreply@tm.openai.com",
                            "subject": "Your ChatGPT code is 111111",
                            "text": "Your ChatGPT code is 111111",
                            "date": "2026-04-03T04:43:54Z",
                        },
                        {
                            "send": "noreply@tm.openai.com",
                            "subject": "Your ChatGPT code is 584863",
                            "text": "Your ChatGPT code is 584863",
                            "date": "2026-04-03T04:44:54Z",
                        },
                    ],
                }

        session = mock.Mock()
        session.get.return_value = _Resp()
        mailbox._session = mock.Mock(return_value=session)

        with mock.patch("time.sleep", return_value=None):
            code = mailbox.wait_for_code(
                MailboxAccount(email="demo@example.com", account_id="demo@example.com"),
                timeout=1,
            )

        self.assertEqual(code, "584863")

    def test_fetch_latest_supports_top_level_list_payload(self):
        mailbox = self._build_mailbox()

        class _Resp:
            status_code = 200
            text = ""

            def json(self):
                return [
                    {
                        "send": "noreply@tm.openai.com",
                        "subject": "Your ChatGPT code is 111111",
                        "text": "Your ChatGPT code is 111111",
                        "date": "2026-04-03T04:43:54Z",
                    },
                    {
                        "send": "noreply@tm.openai.com",
                        "subject": "Your ChatGPT code is 584863",
                        "text": "Your ChatGPT code is 584863",
                        "date": "2026-04-03T04:44:54Z",
                    },
                ]

        session = mock.Mock()
        session.get.return_value = _Resp()
        mailbox._session = mock.Mock(return_value=session)

        msg = mailbox._fetch_latest(mailbox._accounts[0], "INBOX")

        self.assertEqual(msg["subject"], "Your ChatGPT code is 584863")
        self.assertEqual(mailbox._safe_extract(msg.get("text") or msg.get("subject")), "584863")

    def test_wait_for_code_falls_back_to_mail_all_and_verification_code_field(self):
        mailbox = self._build_mailbox()

        class _RespLatest:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "code": 200,
                    "success": True,
                    "data": {
                        "subject": "Newsletter",
                        "text": "No otp here",
                        "date": "2026-04-03T04:45:54Z",
                    },
                }

        class _RespAll:
            status_code = 200
            text = ""

            def json(self):
                return {
                    "code": 200,
                    "success": True,
                    "data": [
                        {
                            "subject": "Older message",
                            "text": "No otp",
                            "date": "2026-04-03T04:43:54Z",
                        },
                        {
                            "subject": "OpenAI verification",
                            "preview": "Use code 654321",
                            "verification_code": "654321",
                            "date": "2026-04-03T04:44:54Z",
                        },
                    ],
                }

        def _get(url, **kwargs):
            if url.endswith('/api/mail-new'):
                return _RespLatest()
            if url.endswith('/api/mail-all'):
                return _RespAll()
            raise AssertionError(url)

        session = mock.Mock()
        session.get.side_effect = _get
        mailbox._session = mock.Mock(return_value=session)

        with mock.patch("time.sleep", return_value=None):
            code = mailbox.wait_for_code(
                MailboxAccount(email="demo@example.com", account_id="demo@example.com"),
                timeout=1,
            )

        self.assertEqual(code, "654321")

    def test_wait_for_code_raises_invalid_credential_on_invalid_grant(self):
        mailbox = self._build_mailbox()

        class _RespInvalidGrant:
            status_code = 500
            text = (
                '{"code":500,"success":false,"data":{"error":"HTTP error! status: 400, '
                'response: {\\"error\\":\\"invalid_grant\\",'
                '\\"error_description\\":\\"AADSTS70000\\"}"}}'
            )

            def json(self):
                raise AssertionError("invalid_grant 响应不应继续解析 JSON")

        session = mock.Mock()
        session.get.return_value = _RespInvalidGrant()
        mailbox._session = mock.Mock(return_value=session)

        with mock.patch("time.sleep", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                mailbox.wait_for_code(
                    MailboxAccount(email="demo@example.com", account_id="demo@example.com"),
                    timeout=1,
                )

        self.assertIn("invalid_grant", str(ctx.exception))

    def test_wait_for_code_raises_runtime_error_when_not_connected(self):
        mailbox = self._build_mailbox()

        class _RespNotConnected:
            status_code = 500
            text = '{"code":500,"success":false,"data":{"error":"User is authenticated but not connected."}}'

            def json(self):
                raise AssertionError("not connected 响应不应继续解析 JSON")

        session = mock.Mock()
        session.get.return_value = _RespNotConnected()
        mailbox._session = mock.Mock(return_value=session)

        with mock.patch("time.sleep", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                mailbox.wait_for_code(
                    MailboxAccount(email="demo@example.com", account_id="demo@example.com"),
                    timeout=1,
                )

        self.assertIn("未连接", str(ctx.exception))

    def test_wait_for_code_raises_runtime_error_on_command_error_12(self):
        mailbox = self._build_mailbox()

        class _RespCommandError:
            status_code = 500
            text = '{"code":500,"success":false,"data":{"error":"Command Error. 12"}}'

            def json(self):
                raise AssertionError("command error 响应不应继续解析 JSON")

        session = mock.Mock()
        session.get.return_value = _RespCommandError()
        mailbox._session = mock.Mock(return_value=session)

        with mock.patch("time.sleep", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                mailbox.wait_for_code(
                    MailboxAccount(email="demo@example.com", account_id="demo@example.com"),
                    timeout=1,
                )

        self.assertIn("Command Error. 12", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
