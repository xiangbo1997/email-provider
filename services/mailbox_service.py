from __future__ import annotations

import json
import os
import secrets
import uuid

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlmodel import Field, SQLModel, Session, create_engine, select


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _json_loads(value: str, default: Any) -> Any:
    try:
        loaded = json.loads(value or "")
    except Exception:
        return default
    return loaded if loaded is not None else default


def _create_mailbox_service_engine():
    database_url = os.getenv("MAILBOX_SERVICE_DATABASE_URL", "sqlite:///mailbox_service.db")
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    return create_engine(database_url, connect_args=connect_args)


mailbox_service_engine = _create_mailbox_service_engine()


class MailboxSessionModel(SQLModel, table=True):
    __tablename__ = "mailbox_service_sessions"

    session_id: str = Field(primary_key=True)
    lease_token: str
    provider: str = Field(index=True)
    email: str = Field(index=True)
    account_id: str = ""
    purpose: str = ""
    state: str = Field(default="leased", index=True)
    result: str = ""
    proxy: str = ""
    config_json: str = "{}"
    account_extra_json: str = "{}"
    before_ids_json: str = "[]"
    provider_meta_json: str = "{}"
    error_code: str = ""
    error_message: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    expires_at: datetime = Field(default_factory=lambda: _utcnow() + timedelta(minutes=15))
    completed_at: Optional[datetime] = None


class MailboxSessionEventModel(SQLModel, table=True):
    __tablename__ = "mailbox_service_session_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True)
    event_type: str = Field(index=True)
    detail_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)


class MailboxProviderConfigModel(SQLModel, table=True):
    __tablename__ = "mailbox_provider_configs"

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    provider: str = Field(index=True)
    enabled: bool = Field(default=True, index=True)
    description: str = ""
    proxy: str = ""
    extra_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_validated_at: Optional[datetime] = None
    last_validation_ok: Optional[bool] = None
    last_validation_message: str = ""


@dataclass
class MailboxLease:
    session_id: str
    lease_token: str
    provider: str
    email: str
    account_id: str = ""
    state: str = "leased"
    expires_at: datetime = field(default_factory=lambda: _utcnow() + timedelta(minutes=15))
    before_ids: list[str] = field(default_factory=list)
    provider_meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class MailboxPollResult:
    status: str
    code: str = ""
    message: str = ""
    matched_mailbox: str = ""
    error_code: str = ""


class MailboxServiceError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


PROVIDER_CATALOG: dict[str, dict[str, Any]] = {
    "laoudo": {
        "description": "固定 laoudo 账号，适合直接绑定既有邮箱。",
        "fields": [
            {"key": "laoudo_auth", "label": "Auth Token", "secret": True},
            {"key": "laoudo_email", "label": "Email"},
            {"key": "laoudo_account_id", "label": "Account ID"},
        ],
        "example_extra": {
            "laoudo_auth": "",
            "laoudo_email": "",
            "laoudo_account_id": "",
        },
    },
    "tempmail_lol": {
        "description": "无需额外配置的临时邮箱源。",
        "fields": [],
        "example_extra": {},
    },
    "skymail": {
        "description": "SkyMail API 配置。",
        "fields": [
            {"key": "skymail_api_base", "label": "API Base"},
            {"key": "skymail_token", "label": "Token", "secret": True},
            {"key": "skymail_domain", "label": "Domain"},
        ],
        "example_extra": {
            "skymail_api_base": "https://api.skymail.ink",
            "skymail_token": "",
            "skymail_domain": "",
        },
    },
    "duckmail": {
        "description": "DuckMail 兼容源，支持 bearer 或独立 API Key。",
        "fields": [
            {"key": "duckmail_api_url", "label": "API URL"},
            {"key": "duckmail_provider_url", "label": "Provider URL"},
            {"key": "duckmail_bearer", "label": "Bearer", "secret": True},
            {"key": "duckmail_domain", "label": "Domain"},
            {"key": "duckmail_api_key", "label": "API Key", "secret": True},
        ],
        "example_extra": {
            "duckmail_api_url": "https://www.duckmail.sbs",
            "duckmail_provider_url": "https://api.duckmail.sbs",
            "duckmail_bearer": "",
            "duckmail_domain": "",
            "duckmail_api_key": "",
        },
    },
    "freemail": {
        "description": "自托管 Freemail 风格接口。",
        "fields": [
            {"key": "freemail_api_url", "label": "API URL"},
            {"key": "freemail_admin_token", "label": "Admin Token", "secret": True},
            {"key": "freemail_username", "label": "Username"},
            {"key": "freemail_password", "label": "Password", "secret": True},
        ],
        "example_extra": {
            "freemail_api_url": "",
            "freemail_admin_token": "",
            "freemail_username": "",
            "freemail_password": "",
        },
    },
    "moemail": {
        "description": "MoeMail 风格接口。",
        "fields": [
            {"key": "moemail_api_url", "label": "API URL"},
        ],
        "example_extra": {
            "moemail_api_url": "https://sall.cc",
        },
    },
    "maliapi": {
        "description": "MaliAPI 风格接口。",
        "fields": [
            {"key": "maliapi_base_url", "label": "Base URL"},
            {"key": "maliapi_api_key", "label": "API Key", "secret": True},
            {"key": "maliapi_domain", "label": "Domain"},
            {"key": "maliapi_auto_domain_strategy", "label": "Auto Domain Strategy"},
        ],
        "example_extra": {
            "maliapi_base_url": "https://maliapi.215.im/v1",
            "maliapi_api_key": "",
            "maliapi_domain": "",
            "maliapi_auto_domain_strategy": "",
        },
    },
    "cfworker": {
        "description": "Cloudflare Worker 邮箱桥。",
        "fields": [
            {"key": "cfworker_api_url", "label": "API URL"},
            {"key": "cfworker_admin_token", "label": "Admin Token", "secret": True},
            {"key": "cfworker_domain", "label": "Domain"},
            {"key": "cfworker_domain_override", "label": "Domain Override"},
            {"key": "cfworker_domains", "label": "Domains"},
            {"key": "cfworker_enabled_domains", "label": "Enabled Domains"},
            {"key": "cfworker_fingerprint", "label": "Fingerprint"},
            {"key": "cfworker_custom_auth", "label": "Custom Auth", "secret": True},
        ],
        "example_extra": {
            "cfworker_api_url": "",
            "cfworker_admin_token": "",
            "cfworker_domain": "",
            "cfworker_domain_override": "",
            "cfworker_domains": "",
            "cfworker_enabled_domains": "",
            "cfworker_fingerprint": "",
            "cfworker_custom_auth": "",
        },
    },
    "luckmail": {
        "description": "LuckMail API，适合已知邮箱上下文二次取码。",
        "fields": [
            {"key": "luckmail_base_url", "label": "Base URL"},
            {"key": "luckmail_api_key", "label": "API Key", "secret": True},
            {"key": "luckmail_project_code", "label": "Project Code"},
            {"key": "luckmail_email_type", "label": "Email Type"},
            {"key": "luckmail_domain", "label": "Domain"},
        ],
        "example_extra": {
            "luckmail_base_url": "https://mails.luckyous.com/",
            "luckmail_api_key": "",
            "luckmail_project_code": "",
            "luckmail_email_type": "",
            "luckmail_domain": "",
        },
    },
    "qqemail": {
        "description": "QQEmail 风格接口。",
        "fields": [
            {"key": "qqemail_api_url", "label": "API URL"},
            {"key": "qqemail_username", "label": "Username"},
            {"key": "qqemail_password", "label": "Password", "secret": True},
            {"key": "qqemail_domain", "label": "Domain"},
        ],
        "example_extra": {
            "qqemail_api_url": "https://qqemail.eu.org",
            "qqemail_username": "",
            "qqemail_password": "",
            "qqemail_domain": "qqemail.eu.org",
        },
    },
    "applemail": {
        "description": "AppleMail 账号池，账号串直接存到 applemail_accounts。",
        "fields": [
            {"key": "applemail_accounts", "label": "Accounts", "secret": True, "multiline": True},
        ],
        "example_extra": {
            "applemail_accounts": "user@example.com----password----client_id----refresh_token",
        },
    },
}


class MailboxService:
    SUPPORTED_PROVIDERS = (
        "laoudo",
        "tempmail_lol",
        "skymail",
        "duckmail",
        "freemail",
        "moemail",
        "maliapi",
        "cfworker",
        "luckmail",
        "qqemail",
        "applemail",
    )

    def init_db(self) -> None:
        MailboxSessionModel.__table__.create(mailbox_service_engine, checkfirst=True)
        MailboxSessionEventModel.__table__.create(mailbox_service_engine, checkfirst=True)
        MailboxProviderConfigModel.__table__.create(mailbox_service_engine, checkfirst=True)

    def list_providers(self) -> list[dict[str, Any]]:
        return [{"name": name, "mode": "legacy_adapter"} for name in self.SUPPORTED_PROVIDERS]

    def provider_catalog(self) -> list[dict[str, Any]]:
        items = []
        for name in self.SUPPORTED_PROVIDERS:
            spec = PROVIDER_CATALOG.get(name, {})
            items.append(
                {
                    "name": name,
                    "mode": "legacy_adapter",
                    "description": str(spec.get("description") or ""),
                    "fields": list(spec.get("fields") or []),
                    "example_extra": dict(spec.get("example_extra") or {}),
                }
            )
        return items

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "providers": list(self.SUPPORTED_PROVIDERS),
            "database_url": os.getenv("MAILBOX_SERVICE_DATABASE_URL", "sqlite:///mailbox_service.db"),
        }

    def validate_provider(self, provider: str) -> None:
        if provider not in self.SUPPORTED_PROVIDERS:
            raise MailboxServiceError("UNSUPPORTED_PROVIDER", f"不支持的邮箱 provider: {provider}")

    def validate_provider_config(
        self,
        *,
        provider: str,
        extra: Optional[dict[str, Any]] = None,
        proxy: Optional[str] = None,
    ) -> dict[str, Any]:
        self.validate_provider(provider)
        self._create_local_mailbox(provider=provider, extra=dict(extra or {}), proxy=proxy)
        return {"ok": True, "provider": provider}

    def list_provider_configs(self) -> list[dict[str, Any]]:
        with Session(mailbox_service_engine) as session:
            stmt = select(MailboxProviderConfigModel).order_by(
                MailboxProviderConfigModel.updated_at.desc(),
                MailboxProviderConfigModel.id.desc(),
            )
            return [self._to_provider_config(item) for item in session.exec(stmt).all()]

    def get_provider_config(self, config_id: int) -> dict[str, Any]:
        with Session(mailbox_service_engine) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
            return self._to_provider_config(model)

    def create_provider_config(
        self,
        *,
        name: str,
        provider: str,
        extra: Optional[dict[str, Any]] = None,
        proxy: Optional[str] = None,
        description: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:
        clean_name = str(name or "").strip()
        if not clean_name:
            raise MailboxServiceError("PROVIDER_CONFIG_NAME_REQUIRED", "provider 配置名称不能为空")
        self.validate_provider(provider)
        model = MailboxProviderConfigModel(
            name=clean_name,
            provider=provider,
            enabled=bool(enabled),
            description=str(description or "").strip(),
            proxy=str(proxy or ""),
            extra_json=_json_dumps(dict(extra or {})),
        )
        try:
            with Session(mailbox_service_engine) as session:
                session.add(model)
                session.commit()
                session.refresh(model)
                return self._to_provider_config(model)
        except IntegrityError as exc:
            raise MailboxServiceError("PROVIDER_CONFIG_NAME_EXISTS", f"provider 配置名称已存在: {clean_name}") from exc

    def update_provider_config(
        self,
        config_id: int,
        *,
        name: str,
        provider: str,
        extra: Optional[dict[str, Any]] = None,
        proxy: Optional[str] = None,
        description: str = "",
        enabled: bool = True,
    ) -> dict[str, Any]:
        clean_name = str(name or "").strip()
        if not clean_name:
            raise MailboxServiceError("PROVIDER_CONFIG_NAME_REQUIRED", "provider 配置名称不能为空")
        self.validate_provider(provider)
        try:
            with Session(mailbox_service_engine) as session:
                model = session.get(MailboxProviderConfigModel, config_id)
                if not model:
                    raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
                model.name = clean_name
                model.provider = provider
                model.enabled = bool(enabled)
                model.description = str(description or "").strip()
                model.proxy = str(proxy or "")
                model.extra_json = _json_dumps(dict(extra or {}))
                model.updated_at = _utcnow()
                session.add(model)
                session.commit()
                session.refresh(model)
                return self._to_provider_config(model)
        except IntegrityError as exc:
            raise MailboxServiceError("PROVIDER_CONFIG_NAME_EXISTS", f"provider 配置名称已存在: {clean_name}") from exc

    def delete_provider_config(self, config_id: int) -> None:
        with Session(mailbox_service_engine) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
            session.delete(model)
            session.commit()

    def validate_saved_provider_config(self, config_id: int) -> dict[str, Any]:
        with Session(mailbox_service_engine) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")

        try:
            result = self.validate_provider_config(
                provider=model.provider,
                extra=_json_loads(model.extra_json, {}),
                proxy=model.proxy or None,
            )
            ok = True
            message = "ok"
        except Exception as exc:
            result = {"ok": False, "provider": model.provider}
            ok = False
            message = str(exc)

        with Session(mailbox_service_engine) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
            model.last_validated_at = _utcnow()
            model.last_validation_ok = ok
            model.last_validation_message = message
            model.updated_at = _utcnow()
            session.add(model)
            session.commit()
            session.refresh(model)

        response = self._to_provider_config(model)
        response["validation"] = {
            "ok": ok,
            "message": message,
            "provider": result.get("provider", model.provider),
        }
        return response

    def resolve_provider_request(
        self,
        *,
        provider: str | None = None,
        extra: Optional[dict[str, Any]] = None,
        proxy: str | None = None,
        config_id: int | None = None,
        config_name: str | None = None,
    ) -> dict[str, Any]:
        resolved_provider = str(provider or "").strip()
        resolved_extra = dict(extra or {})
        resolved_proxy = proxy
        source_config = None

        if config_id is not None or str(config_name or "").strip():
            source_config = self._get_provider_config_model(
                config_id=config_id,
                config_name=config_name,
                enabled_only=True,
            )
            if resolved_provider and resolved_provider != source_config.provider:
                raise MailboxServiceError(
                    "PROVIDER_CONFIG_PROVIDER_MISMATCH",
                    f"provider 与保存配置不一致: {resolved_provider} != {source_config.provider}",
                )
            resolved_provider = source_config.provider
            merged_extra = _json_loads(source_config.extra_json, {})
            merged_extra.update(resolved_extra)
            resolved_extra = merged_extra
            if resolved_proxy is None:
                resolved_proxy = source_config.proxy or None

        if not resolved_provider:
            raise MailboxServiceError("PROVIDER_REQUIRED", "必须提供 provider，或通过 config_id/config_name 指定保存配置")

        self.validate_provider(resolved_provider)
        return {
            "provider": resolved_provider,
            "extra": resolved_extra,
            "proxy": resolved_proxy,
            "config": self._to_provider_config(source_config) if source_config else None,
        }

    def list_recent_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit or 50), 200))
        with Session(mailbox_service_engine) as session:
            stmt = select(MailboxSessionModel).order_by(
                MailboxSessionModel.created_at.desc(),
            ).limit(safe_limit)
            return [self._to_session_summary(item) for item in session.exec(stmt).all()]

    def acquire_session(
        self,
        *,
        provider: str,
        extra: Optional[dict[str, Any]] = None,
        proxy: Optional[str] = None,
        purpose: str = "generic",
        account_override: Any = None,
        lease_seconds: int = 900,
    ) -> MailboxLease:
        self.validate_provider(provider)
        extra = dict(extra or {})
        mailbox = self._create_local_mailbox(provider=provider, extra=extra, proxy=proxy)

        if account_override is None:
            account = mailbox.get_email()
            try:
                before_ids = sorted(str(item) for item in (mailbox.get_current_ids(account) or set()) if str(item))
            except Exception:
                before_ids = []
        else:
            from core.base_mailbox import MailboxAccount

            if isinstance(account_override, MailboxAccount):
                account = account_override
            else:
                account = MailboxAccount(
                    email=str(getattr(account_override, "email", "") or ""),
                    account_id=str(getattr(account_override, "account_id", "") or ""),
                    extra=getattr(account_override, "extra", None),
                )
            self._prepare_known_account(mailbox, account)
            try:
                before_ids = sorted(str(item) for item in (mailbox.get_current_ids(account) or set()) if str(item))
            except Exception:
                before_ids = []

        provider_meta = self._extract_provider_meta(mailbox=mailbox, account=account)
        expires_at = _utcnow() + timedelta(seconds=max(30, int(lease_seconds or 900)))
        lease = MailboxLease(
            session_id=uuid.uuid4().hex,
            lease_token=secrets.token_urlsafe(24),
            provider=provider,
            email=account.email,
            account_id=str(account.account_id or ""),
            state="leased",
            expires_at=expires_at,
            before_ids=before_ids,
            provider_meta=provider_meta,
        )
        with Session(mailbox_service_engine) as session:
            model = MailboxSessionModel(
                session_id=lease.session_id,
                lease_token=lease.lease_token,
                provider=provider,
                email=lease.email,
                account_id=lease.account_id,
                purpose=purpose,
                state=lease.state,
                proxy=str(proxy or ""),
                config_json=_json_dumps(extra),
                account_extra_json=_json_dumps(account.extra or {}),
                before_ids_json=_json_dumps(before_ids),
                provider_meta_json=_json_dumps(provider_meta),
                expires_at=expires_at,
            )
            session.add(model)
            session.commit()
        self._record_event(lease.session_id, "created", {"email": lease.email, "provider": provider})
        return lease

    def get_session(self, session_id: str) -> MailboxLease:
        with Session(mailbox_service_engine) as session:
            model = session.get(MailboxSessionModel, session_id)
            if not model:
                raise MailboxServiceError("SESSION_NOT_FOUND", f"未找到会话: {session_id}")
            self._expire_if_needed(session, model)
            return self._to_lease(model)

    def poll_code(
        self,
        *,
        session_id: str,
        lease_token: str,
        timeout_seconds: int = 120,
        keyword: str = "",
        code_pattern: str | None = None,
        otp_sent_at: float | None = None,
        exclude_codes: Optional[set[str]] = None,
        before_ids: Optional[set[str]] = None,
    ) -> MailboxPollResult:
        with Session(mailbox_service_engine) as session:
            model = self._get_session_model(session, session_id, lease_token)
            model.state = "polling"
            model.updated_at = _utcnow()
            session.add(model)
            session.commit()

        model = self.get_session_model(session_id, lease_token)
        mailbox, account, snapshot_ids = self._hydrate_runtime(model)
        used_before_ids = set(before_ids or snapshot_ids)
        try:
            code = mailbox.wait_for_code(
                account,
                keyword=keyword,
                timeout=int(timeout_seconds or 120),
                before_ids=used_before_ids,
                code_pattern=code_pattern,
                otp_sent_at=otp_sent_at,
                exclude_codes=exclude_codes or set(),
            )
        except Exception as exc:
            error_code = self._map_error_code(exc)
            message = str(exc)
            with Session(mailbox_service_engine) as session:
                model = self._get_session_model(session, session_id, lease_token)
                model.state = "failed"
                model.error_code = error_code
                model.error_message = message
                model.updated_at = _utcnow()
                session.add(model)
                session.commit()
            self._record_event(session_id, "poll_failed", {"error_code": error_code, "message": message})
            return MailboxPollResult(status="failed", message=message, error_code=error_code)

        with Session(mailbox_service_engine) as session:
            model = self._get_session_model(session, session_id, lease_token)
            model.state = "code_ready"
            model.error_code = ""
            model.error_message = ""
            model.updated_at = _utcnow()
            session.add(model)
            session.commit()
        self._record_event(session_id, "code_ready", {"code": "***"})
        return MailboxPollResult(status="ready", code=str(code or ""))

    def complete_session(
        self,
        *,
        session_id: str,
        lease_token: str,
        result: str,
        reason: str = "",
    ) -> MailboxLease:
        with Session(mailbox_service_engine) as session:
            model = self._get_session_model(session, session_id, lease_token)
            if model.completed_at:
                return self._to_lease(model)

        if str(result or "").lower() == "success":
            try:
                mailbox, account, _ = self._hydrate_runtime(self.get_session_model(session_id, lease_token))
                self._prepare_selected_account(mailbox, account.email)
                if hasattr(mailbox, "remove_used_account"):
                    mailbox.remove_used_account()
            except Exception as exc:
                self._record_event(session_id, "cleanup_failed", {"message": str(exc)})

        with Session(mailbox_service_engine) as session:
            model = self._get_session_model(session, session_id, lease_token)
            model.result = str(result or "").strip().lower()
            model.state = "completed"
            model.completed_at = _utcnow()
            model.updated_at = _utcnow()
            if reason:
                model.error_message = reason
            session.add(model)
            session.commit()
            lease = self._to_lease(model)
        self._record_event(session_id, "completed", {"result": result, "reason": reason})
        return lease

    def get_session_model(self, session_id: str, lease_token: str) -> MailboxSessionModel:
        with Session(mailbox_service_engine) as session:
            model = self._get_session_model(session, session_id, lease_token)
            session.expunge(model)
            return model

    def _hydrate_runtime(self, model: MailboxSessionModel):
        from core.base_mailbox import MailboxAccount

        extra = _json_loads(model.config_json, {})
        account_extra = _json_loads(model.account_extra_json, {})
        before_ids = set(_json_loads(model.before_ids_json, []))
        mailbox = self._create_local_mailbox(provider=model.provider, extra=extra, proxy=model.proxy or None)
        account = MailboxAccount(
            email=model.email,
            account_id=model.account_id or "",
            extra=account_extra or None,
        )
        return mailbox, account, before_ids

    def _create_local_mailbox(self, *, provider: str, extra: dict[str, Any], proxy: Optional[str]):
        from core.base_mailbox import create_local_mailbox

        return create_local_mailbox(provider=provider, extra=extra, proxy=proxy)

    def _extract_provider_meta(self, *, mailbox, account) -> dict[str, Any]:
        provider_meta: dict[str, Any] = {}
        if isinstance(getattr(account, "extra", None), dict):
            provider_meta.update(account.extra)

        for source_attr, target_key in (
            ("_token", "mailbox_token"),
            ("_order_no", "mailbox_order_no"),
            ("_email", "allocated_email"),
        ):
            value = getattr(mailbox, source_attr, "")
            if value:
                provider_meta[target_key] = str(value)
        if account.account_id:
            provider_meta.setdefault("mailbox_token", str(account.account_id))
        provider_meta.setdefault("source_email", str(account.email or ""))
        return provider_meta

    def _prepare_selected_account(self, mailbox, email: str) -> None:
        accounts = getattr(mailbox, "_accounts", None)
        if not isinstance(accounts, list):
            return
        target_email = str(email or "").strip().lower()
        for item in accounts:
            if str((item or {}).get("email", "")).strip().lower() == target_email:
                try:
                    mailbox._selected = item
                except Exception:
                    pass
                return

    def _prepare_known_account(self, mailbox, account) -> None:
        self._prepare_selected_account(mailbox, account.email)

        account_id = str(account.account_id or "").strip()
        if account_id and hasattr(mailbox, "_token"):
            try:
                mailbox._token = account_id
            except Exception:
                pass
        if account.email and hasattr(mailbox, "_email"):
            try:
                mailbox._email = account.email
            except Exception:
                pass

        selected = getattr(mailbox, "_selected", None)
        if selected and hasattr(mailbox, "_clear_mailbox"):
            try:
                mailbox._clear_mailbox(selected)
            except Exception:
                pass

    def _record_event(self, session_id: str, event_type: str, detail: dict[str, Any]) -> None:
        with Session(mailbox_service_engine) as session:
            session.add(
                MailboxSessionEventModel(
                    session_id=session_id,
                    event_type=event_type,
                    detail_json=_json_dumps(detail),
                )
            )
            session.commit()

    def _expire_if_needed(self, session: Session, model: MailboxSessionModel) -> None:
        if model.completed_at:
            return
        if _ensure_utc(model.expires_at) > _utcnow():
            return
        model.state = "expired"
        model.updated_at = _utcnow()
        session.add(model)
        session.commit()
        raise MailboxServiceError("LEASE_EXPIRED", f"邮箱会话已过期: {model.session_id}")

    def _get_session_model(self, session: Session, session_id: str, lease_token: str) -> MailboxSessionModel:
        model = session.get(MailboxSessionModel, session_id)
        if not model:
            raise MailboxServiceError("SESSION_NOT_FOUND", f"未找到会话: {session_id}")
        if model.lease_token != lease_token:
            raise MailboxServiceError("INVALID_LEASE", "邮箱会话租约无效")
        self._expire_if_needed(session, model)
        return model

    def _to_lease(self, model: MailboxSessionModel) -> MailboxLease:
        return MailboxLease(
            session_id=model.session_id,
            lease_token=model.lease_token,
            provider=model.provider,
            email=model.email,
            account_id=model.account_id or "",
            state=model.state,
            expires_at=_ensure_utc(model.expires_at),
            before_ids=list(_json_loads(model.before_ids_json, [])),
            provider_meta=dict(_json_loads(model.provider_meta_json, {})),
        )

    def _to_provider_config(self, model: MailboxProviderConfigModel | None) -> dict[str, Any] | None:
        if model is None:
            return None
        return {
            "id": model.id,
            "name": model.name,
            "provider": model.provider,
            "enabled": bool(model.enabled),
            "description": model.description,
            "proxy": model.proxy,
            "extra": dict(_json_loads(model.extra_json, {})),
            "created_at": _ensure_utc(model.created_at).isoformat(),
            "updated_at": _ensure_utc(model.updated_at).isoformat(),
            "last_validated_at": _ensure_utc(model.last_validated_at).isoformat() if model.last_validated_at else None,
            "last_validation_ok": model.last_validation_ok,
            "last_validation_message": model.last_validation_message,
        }

    def _to_session_summary(self, model: MailboxSessionModel) -> dict[str, Any]:
        return {
            "session_id": model.session_id,
            "provider": model.provider,
            "email": model.email,
            "purpose": model.purpose,
            "state": model.state,
            "result": model.result,
            "error_code": model.error_code,
            "error_message": model.error_message,
            "created_at": _ensure_utc(model.created_at).isoformat(),
            "updated_at": _ensure_utc(model.updated_at).isoformat(),
            "expires_at": _ensure_utc(model.expires_at).isoformat(),
            "completed_at": _ensure_utc(model.completed_at).isoformat() if model.completed_at else None,
        }

    def _get_provider_config_model(
        self,
        *,
        config_id: int | None = None,
        config_name: str | None = None,
        enabled_only: bool = False,
    ) -> MailboxProviderConfigModel:
        with Session(mailbox_service_engine) as session:
            model = None
            if config_id is not None:
                model = session.get(MailboxProviderConfigModel, config_id)
            elif str(config_name or "").strip():
                stmt = select(MailboxProviderConfigModel).where(
                    MailboxProviderConfigModel.name == str(config_name).strip()
                )
                model = session.exec(stmt).first()

            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", "未找到指定的 provider 配置")
            if enabled_only and not model.enabled:
                raise MailboxServiceError("PROVIDER_CONFIG_DISABLED", f"provider 配置已禁用: {model.name}")
            session.expunge(model)
            return model

    def _map_error_code(self, exc: Exception) -> str:
        text = str(exc or "").strip().lower()
        if "invalid_grant" in text or "aadsts70000" in text:
            return "INVALID_CREDENTIAL"
        if "lease" in text and "expire" in text:
            return "LEASE_EXPIRED"
        if "超时" in text or "timed out" in text or isinstance(exc, TimeoutError):
            return "CODE_TIMEOUT"
        if "429" in text or "rate limit" in text:
            return "RATE_LIMITED"
        if "500" in text or "502" in text or "503" in text or "504" in text:
            return "UPSTREAM_5XX"
        return "PROVIDER_ERROR"


mailbox_service = MailboxService()


def init_mailbox_service_db() -> None:
    mailbox_service.init_db()
