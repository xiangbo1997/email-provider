from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import Field, SQLModel, Session, select

from services.crypto_utils import hash_token, redact_structure
from services.database import get_mailbox_service_engine


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AdminWebSessionModel(SQLModel, table=True):
    __tablename__ = "admin_web_sessions"

    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True)
    session_token_hash: str = Field(index=True, unique=True)
    csrf_token_hash: str = Field(index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    last_seen_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime = Field(default_factory=lambda: _utcnow() + timedelta(hours=8))
    revoked_at: Optional[datetime] = None
    ip_hash: str = Field(default="", index=True)
    user_agent_hash: str = ""


class AdminAuthEventModel(SQLModel, table=True):
    __tablename__ = "admin_auth_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    event_type: str = Field(index=True)
    username: str = Field(default="", index=True)
    session_id: Optional[int] = Field(default=None, index=True)
    ip_hash: str = Field(default="", index=True)
    user_agent_hash: str = ""
    detail_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)


class AdminLoginAttemptModel(SQLModel, table=True):
    __tablename__ = "admin_login_attempts"

    id: Optional[int] = Field(default=None, primary_key=True)
    ip_hash: str = Field(index=True, unique=True)
    window_started_at: datetime = Field(default_factory=_utcnow)
    failed_count: int = 0
    blocked_until: Optional[datetime] = None
    updated_at: datetime = Field(default_factory=_utcnow)


@dataclass
class AdminSessionIdentity:
    session_id: int
    username: str
    expires_at: datetime


class AdminAuthError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class AdminAuthService:
    SESSION_COOKIE_NAME = "email_provider_admin_session"
    CSRF_COOKIE_NAME = "email_provider_admin_csrf"
    LOGIN_WINDOW = timedelta(minutes=15)
    LOGIN_LOCK_DURATION = timedelta(minutes=15)
    LOGIN_MAX_FAILURES = 5

    def init_db(self) -> None:
        engine = get_mailbox_service_engine()
        AdminWebSessionModel.__table__.create(engine, checkfirst=True)
        AdminAuthEventModel.__table__.create(engine, checkfirst=True)
        AdminLoginAttemptModel.__table__.create(engine, checkfirst=True)

    def is_configured(self) -> bool:
        return bool(self._expected_username() and self._expected_password_hash())

    def create_password_hash(self, password: str, *, n: int = 16384, r: int = 8, p: int = 1) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
        return "$".join(
            [
                "scrypt",
                str(n),
                str(r),
                str(p),
                base64.urlsafe_b64encode(salt).decode("ascii"),
                base64.urlsafe_b64encode(digest).decode("ascii"),
            ]
        )

    def verify_password_hash(self, password: str, encoded_hash: str | None) -> bool:
        text = str(encoded_hash or "").strip()
        try:
            algorithm, n_text, r_text, p_text, salt_b64, digest_b64 = text.split("$", 5)
        except ValueError:
            return False
        if algorithm != "scrypt":
            return False
        try:
            n = int(n_text)
            r = int(r_text)
            p = int(p_text)
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
            expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
        except Exception:
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return secrets.compare_digest(actual, expected)

    def login(self, *, username: str, password: str, client_ip: str, user_agent: str) -> tuple[str, str, datetime]:
        if not self.is_configured():
            raise AdminAuthError("ADMIN_AUTH_NOT_CONFIGURED", "admin login is not configured", 503)

        ip_hash = hash_token(client_ip)
        user_agent_hash = hash_token(user_agent)
        now = _utcnow()
        with Session(get_mailbox_service_engine()) as session:
            attempt = self._get_login_attempt(session, ip_hash)
            blocked_until = _ensure_utc(attempt.blocked_until) if attempt else None
            if blocked_until and blocked_until > now:
                self._record_event(
                    session,
                    event_type="login_rate_limited",
                    username=username,
                    ip_hash=ip_hash,
                    user_agent_hash=user_agent_hash,
                    detail={"blocked_until": blocked_until.isoformat()},
                )
                session.commit()
                raise AdminAuthError("RATE_LIMITED", "too many failed login attempts", 429)

            username_ok = secrets.compare_digest(str(username or ""), self._expected_username())
            password_ok = self.verify_password_hash(password, self._expected_password_hash())
            if not (username_ok and password_ok):
                self._register_failed_attempt(session, ip_hash, username, user_agent_hash)
                session.commit()
                raise AdminAuthError("INVALID_ADMIN_CREDENTIALS", "invalid username or password", 401)

            self._clear_login_attempt(session, ip_hash)
            session_token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(32)
            expires_at = now + timedelta(seconds=self._session_ttl_seconds())
            model = AdminWebSessionModel(
                username=self._expected_username(),
                session_token_hash=hash_token(session_token),
                csrf_token_hash=hash_token(csrf_token),
                created_at=now,
                last_seen_at=now,
                expires_at=expires_at,
                ip_hash=ip_hash,
                user_agent_hash=user_agent_hash,
            )
            session.add(model)
            session.flush()
            self._record_event(
                session,
                event_type="login_succeeded",
                username=self._expected_username(),
                session_id=model.id,
                ip_hash=ip_hash,
                user_agent_hash=user_agent_hash,
                detail={"expires_at": expires_at.isoformat()},
            )
            session.commit()
            return session_token, csrf_token, expires_at

    def authenticate_session(self, *, session_token: str, client_ip: str = "", user_agent: str = "") -> AdminSessionIdentity:
        token_hash = hash_token(session_token)
        now = _utcnow()
        with Session(get_mailbox_service_engine()) as session:
            stmt = select(AdminWebSessionModel).where(AdminWebSessionModel.session_token_hash == token_hash)
            model = session.exec(stmt).first()
            if not model or model.revoked_at:
                raise AdminAuthError("UNAUTHORIZED", "invalid admin session", 401)
            expires_at = _ensure_utc(model.expires_at) or now
            if expires_at <= now:
                model.revoked_at = now
                session.add(model)
                self._record_event(
                    session,
                    event_type="session_expired",
                    username=model.username,
                    session_id=model.id,
                    ip_hash=model.ip_hash,
                    user_agent_hash=model.user_agent_hash,
                    detail={},
                )
                session.commit()
                raise AdminAuthError("SESSION_EXPIRED", "admin session has expired", 401)
            model.last_seen_at = now
            if client_ip:
                model.ip_hash = hash_token(client_ip)
            if user_agent:
                model.user_agent_hash = hash_token(user_agent)
            session.add(model)
            session.commit()
            return AdminSessionIdentity(
                session_id=int(model.id or 0),
                username=model.username,
                expires_at=expires_at,
            )

    def validate_csrf(self, *, session_token: str, csrf_cookie: str, csrf_header: str) -> None:
        cookie = str(csrf_cookie or "").strip()
        header = str(csrf_header or "").strip()
        if not cookie or not header or cookie != header:
            raise AdminAuthError("CSRF_FAILED", "missing or invalid csrf token", 403)
        with Session(get_mailbox_service_engine()) as session:
            stmt = select(AdminWebSessionModel).where(AdminWebSessionModel.session_token_hash == hash_token(session_token))
            model = session.exec(stmt).first()
            if not model or model.revoked_at:
                raise AdminAuthError("UNAUTHORIZED", "invalid admin session", 401)
            if not secrets.compare_digest(model.csrf_token_hash, hash_token(cookie)):
                raise AdminAuthError("CSRF_FAILED", "missing or invalid csrf token", 403)

    def logout(self, *, session_token: str, client_ip: str = "", user_agent: str = "") -> None:
        token_hash = hash_token(session_token)
        now = _utcnow()
        ip_hash = hash_token(client_ip) if client_ip else ""
        user_agent_hash = hash_token(user_agent) if user_agent else ""
        with Session(get_mailbox_service_engine()) as session:
            stmt = select(AdminWebSessionModel).where(AdminWebSessionModel.session_token_hash == token_hash)
            model = session.exec(stmt).first()
            if not model:
                return
            model.revoked_at = now
            session.add(model)
            self._record_event(
                session,
                event_type="logout",
                username=model.username,
                session_id=model.id,
                ip_hash=ip_hash or model.ip_hash,
                user_agent_hash=user_agent_hash or model.user_agent_hash,
                detail={},
            )
            session.commit()

    def _expected_username(self) -> str:
        return str(os.getenv("EMAIL_PROVIDER_ADMIN_USERNAME") or "").strip()

    def _expected_password_hash(self) -> str:
        return str(os.getenv("EMAIL_PROVIDER_ADMIN_PASSWORD_HASH") or "").strip()

    def _session_ttl_seconds(self) -> int:
        return max(300, int(os.getenv("EMAIL_PROVIDER_ADMIN_SESSION_TTL_SECONDS") or "28800"))

    def _get_login_attempt(self, session: Session, ip_hash: str) -> AdminLoginAttemptModel | None:
        stmt = select(AdminLoginAttemptModel).where(AdminLoginAttemptModel.ip_hash == ip_hash)
        return session.exec(stmt).first()

    def _clear_login_attempt(self, session: Session, ip_hash: str) -> None:
        attempt = self._get_login_attempt(session, ip_hash)
        if attempt:
            attempt.failed_count = 0
            attempt.blocked_until = None
            attempt.window_started_at = _utcnow()
            attempt.updated_at = _utcnow()
            session.add(attempt)

    def _register_failed_attempt(self, session: Session, ip_hash: str, username: str, user_agent_hash: str) -> None:
        now = _utcnow()
        attempt = self._get_login_attempt(session, ip_hash)
        if not attempt:
            attempt = AdminLoginAttemptModel(
                ip_hash=ip_hash,
                window_started_at=now,
                failed_count=1,
                updated_at=now,
            )
            session.add(attempt)
        else:
            window_started = _ensure_utc(attempt.window_started_at) or now
            if window_started + self.LOGIN_WINDOW <= now:
                attempt.window_started_at = now
                attempt.failed_count = 1
                attempt.blocked_until = None
            else:
                attempt.failed_count += 1
                if attempt.failed_count >= self.LOGIN_MAX_FAILURES:
                    attempt.blocked_until = now + self.LOGIN_LOCK_DURATION
            attempt.updated_at = now
            session.add(attempt)
        self._record_event(
            session,
            event_type="login_failed",
            username=username,
            ip_hash=ip_hash,
            user_agent_hash=user_agent_hash,
            detail={"failed_count": attempt.failed_count},
        )

    def _record_event(
        self,
        session: Session,
        *,
        event_type: str,
        username: str,
        ip_hash: str,
        user_agent_hash: str,
        detail: dict[str, Any],
        session_id: int | None = None,
    ) -> None:
        session.add(
            AdminAuthEventModel(
                event_type=event_type,
                username=str(username or ""),
                session_id=session_id,
                ip_hash=str(ip_hash or ""),
                user_agent_hash=str(user_agent_hash or ""),
                detail_json=json_dumps(redact_structure(detail)),
            )
        )


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)


admin_auth_service = AdminAuthService()


def init_admin_auth_db() -> None:
    admin_auth_service.init_db()
