from __future__ import annotations

import json
import secrets
import uuid

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import inspect, or_, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Field, SQLModel, Session, select

from services.crypto_utils import (
    CryptoConfigError,
    decrypt_json,
    decrypt_string,
    encrypt_json,
    encrypt_string,
    hash_token,
    mask_proxy,
    redact_sensitive_text,
    redact_structure,
)
from services.database import current_database_url, get_mailbox_service_engine


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
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


def _raise_storage_write_error(exc: CryptoConfigError) -> None:
    raise MailboxServiceError("ENCRYPTION_NOT_CONFIGURED", str(exc)) from exc


def _raise_storage_read_error(exc: CryptoConfigError) -> None:
    raise MailboxServiceError("ENCRYPTION_NOT_CONFIGURED", str(exc)) from exc


def _encrypt_string_maybe(value: str | None) -> str:
    return encrypt_string(value)


def _encrypt_json_maybe(value: Any) -> str:
    return encrypt_json(value)


def _decrypt_string_maybe(value: str | None, *, default: str = "") -> str:
    return decrypt_string(value, default=default)


def _decrypt_json_maybe(value: str | None, default: Any) -> Any:
    return decrypt_json(value, default)


class MailboxSessionModel(SQLModel, table=True):
    __tablename__ = "mailbox_service_sessions"

    session_id: str = Field(primary_key=True)
    lease_token: str = ""
    lease_token_hash: str = Field(default="", index=True)
    provider: str = Field(index=True)
    session_mode: str = Field(default="managed", index=True)
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
    session_mode: str = "managed"
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


class MailboxServiceError(Exception):
    """业务可识别异常基类。

    重要：**不再继承 RuntimeError**。历史上 MailboxServiceError 与底层
    各 provider 抛出的裸 RuntimeError 因继承关系错乱，使得端点的
    ``except MailboxServiceError`` 无法 catch RuntimeError，所有底层
    "未配置/上游错"全部以 500 + 裸 ``Internal Server Error`` 暴露。
    现在改为继承 ``Exception``，并在 FastAPI 层用 exception_handler 统一
    映射 4xx；裸 RuntimeError 也由全局 handler 兜底成结构化 500，
    不再暴露 stacktrace 给客户端。
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ProviderConfigIncompleteError(MailboxServiceError):
    """422 — 必填 provider 配置字段缺失。

    抛出时机：``acquire_session`` 前置校验阶段，或底层 provider 实现的
    ``_ensure_*`` 检查发现关键字段为空时。
    客户端处理：fail-fast，不应重试；提示用户去 admin UI 完善配置。
    HTTP 映射：422 PROVIDER_NOT_CONFIGURED。
    """

    def __init__(self, message: str, *, missing_fields: list[str] = ()):
        super().__init__("PROVIDER_NOT_CONFIGURED", message)
        self.missing_fields = list(missing_fields)


class ProviderUpstreamError(MailboxServiceError):
    """424 — provider 上游 API 返回 4xx 业务错误（非可重试）。

    抛出时机：CFWorker / SkyMail 等远端返回 400/422 等，不属于"上游短窗 5xx"。
    客户端处理：fail-fast，不应重试，提示运维检查 provider 配置。
    HTTP 映射：424 PROVIDER_UPSTREAM_ERROR。
    """

    def __init__(self, message: str, *, upstream_status: int = 0):
        super().__init__("PROVIDER_UPSTREAM_ERROR", message)
        self.upstream_status = int(upstream_status or 0)


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

SESSION_MODE_MANAGED = "managed"
SESSION_MODE_CREDENTIALED = "credentialed"
SUPPORTED_SESSION_MODES = (SESSION_MODE_MANAGED, SESSION_MODE_CREDENTIALED)

PROVIDER_SESSION_METADATA: dict[str, dict[str, Any]] = {
    "laoudo": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["fixed_account", "provider_managed"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["laoudo_auth", "laoudo_email", "laoudo_account_id"],
        },
        "notes": "依赖已配置的固定邮箱账号，由服务端持有账号上下文。",
    },
    "tempmail_lol": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {},
        "notes": "无需预置账号，服务端自动生成临时邮箱。",
    },
    "skymail": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["skymail_api_base", "skymail_token", "skymail_domain"],
        },
        "notes": "由服务端调用 provider API 创建新邮箱。",
    },
    "duckmail": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["duckmail_api_url", "duckmail_provider_url"],
        },
        "notes": "由服务端注册新账号并轮询验证码。",
    },
    "freemail": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["freemail_api_url"],
        },
        "notes": "由服务端登录/调用 Freemail 风格接口生成邮箱。",
    },
    "moemail": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["moemail_api_url"],
        },
        "notes": "由服务端调用 MoeMail 风格接口分配邮箱。",
    },
    "maliapi": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["maliapi_base_url", "maliapi_api_key"],
        },
        "notes": "由服务端通过 MaliAPI 创建/分配邮箱。",
    },
    "cfworker": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["cfworker_api_url"],
        },
        "notes": "由服务端调用 CF Worker 接口创建或分配邮箱。",
    },
    "luckmail": {
        "supported_session_modes": [SESSION_MODE_MANAGED, SESSION_MODE_CREDENTIALED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate", "existing_token"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["luckmail_base_url", "luckmail_api_key"],
            SESSION_MODE_CREDENTIALED: ["existing_account.email", "existing_account.account_id"],
        },
        "notes": "同时支持服务端分配邮箱与调用方传入既有 token/邮箱上下文。",
    },
    "qqemail": {
        "supported_session_modes": [SESSION_MODE_MANAGED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["auto_allocate"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["qqemail_api_url", "qqemail_username", "qqemail_password"],
        },
        "notes": "由服务端登录后生成临时邮箱。",
    },
    "applemail": {
        "supported_session_modes": [SESSION_MODE_MANAGED, SESSION_MODE_CREDENTIALED],
        "default_session_mode": SESSION_MODE_MANAGED,
        "capabilities": ["account_pool", "existing_account", "supports_preserve_existing_mail"],
        "required_fields_by_mode": {
            SESSION_MODE_MANAGED: ["applemail_accounts"],
            SESSION_MODE_CREDENTIALED: [
                "existing_account.email",
                "existing_account.credentials.client_id",
                "existing_account.credentials.refresh_token",
            ],
        },
        "notes": "可使用后台账号池轮转，也可由调用方指定邮箱并传入匹配的 OAuth 凭据。",
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
        engine = get_mailbox_service_engine()
        MailboxSessionModel.__table__.create(engine, checkfirst=True)
        MailboxSessionEventModel.__table__.create(engine, checkfirst=True)
        MailboxProviderConfigModel.__table__.create(engine, checkfirst=True)

        inspector = inspect(engine)
        columns = {item.get("name") for item in inspector.get_columns("mailbox_service_sessions")}
        if "lease_token_hash" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE mailbox_service_sessions ADD COLUMN lease_token_hash VARCHAR DEFAULT ''"))
        if "session_mode" not in columns:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE mailbox_service_sessions ADD COLUMN session_mode VARCHAR DEFAULT 'managed'"
                    )
                )

    def provider_session_profile(self, provider: str) -> dict[str, Any]:
        self.validate_provider(provider)
        spec = dict(PROVIDER_CATALOG.get(provider, {}))
        meta = dict(PROVIDER_SESSION_METADATA.get(provider, {}))
        supported = list(meta.get("supported_session_modes") or [SESSION_MODE_MANAGED])
        default_mode = str(meta.get("default_session_mode") or supported[0]).strip() or supported[0]
        required_by_mode = dict(meta.get("required_fields_by_mode") or {})
        capabilities = list(meta.get("capabilities") or [])
        notes = str(meta.get("notes") or "")
        return {
            "supported_session_modes": supported,
            "default_session_mode": default_mode,
            "capabilities": capabilities,
            "required_fields_by_mode": required_by_mode,
            "notes": notes,
            "description": str(spec.get("description") or ""),
            "fields": list(spec.get("fields") or []),
            "example_extra": dict(spec.get("example_extra") or {}),
        }

    def default_session_mode_for_provider(self, provider: str) -> str:
        return str(self.provider_session_profile(provider)["default_session_mode"])

    def supports_session_mode(self, provider: str, session_mode: str) -> bool:
        normalized = str(session_mode or "").strip().lower()
        if normalized not in SUPPORTED_SESSION_MODES:
            return False
        profile = self.provider_session_profile(provider)
        return normalized in set(profile.get("supported_session_modes") or [])

    def normalize_session_mode(self, provider: str, session_mode: str | None = None) -> str:
        normalized = str(session_mode or "").strip().lower()
        if not normalized:
            normalized = self.default_session_mode_for_provider(provider)
        if normalized not in SUPPORTED_SESSION_MODES:
            raise MailboxServiceError("UNSUPPORTED_SESSION_MODE", f"不支持的 session_mode: {session_mode}")
        if not self.supports_session_mode(provider, normalized):
            raise MailboxServiceError(
                "UNSUPPORTED_SESSION_MODE",
                f"provider={provider} 不支持 session_mode={normalized}",
            )
        return normalized

    def list_providers(self) -> list[dict[str, Any]]:
        items = []
        for name in self.SUPPORTED_PROVIDERS:
            profile = self.provider_session_profile(name)
            items.append(
                {
                    "name": name,
                    "mode": "legacy_adapter",
                    "default_session_mode": profile["default_session_mode"],
                    "supported_session_modes": profile["supported_session_modes"],
                    "capabilities": profile["capabilities"],
                }
            )
        return items

    def provider_catalog(self) -> list[dict[str, Any]]:
        items = []
        for name in self.SUPPORTED_PROVIDERS:
            profile = self.provider_session_profile(name)
            items.append(
                {
                    "name": name,
                    "mode": "legacy_adapter",
                    "description": profile["description"],
                    "fields": profile["fields"],
                    "example_extra": profile["example_extra"],
                    "supported_session_modes": profile["supported_session_modes"],
                    "default_session_mode": profile["default_session_mode"],
                    "capabilities": profile["capabilities"],
                    "required_fields_by_mode": profile["required_fields_by_mode"],
                    "notes": profile["notes"],
                }
            )
        return items

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "providers": list(self.SUPPORTED_PROVIDERS),
            "database_url": current_database_url(),
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

    def list_provider_configs(
        self,
        *,
        q: str | None = None,
        provider: str | None = None,
        enabled: bool | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        try:
            with Session(get_mailbox_service_engine()) as session:
                stmt = select(MailboxProviderConfigModel)
                if str(provider or "").strip():
                    stmt = stmt.where(MailboxProviderConfigModel.provider == str(provider).strip())
                if enabled is not None:
                    stmt = stmt.where(MailboxProviderConfigModel.enabled == bool(enabled))
                keyword = str(q or "").strip()
                if keyword:
                    stmt = stmt.where(
                        MailboxProviderConfigModel.name.contains(keyword)
                        | MailboxProviderConfigModel.description.contains(keyword)
                    )
                stmt = stmt.order_by(
                    MailboxProviderConfigModel.updated_at.desc(),
                    MailboxProviderConfigModel.id.desc(),
                )
                stmt = stmt.offset(max(0, int(offset or 0))).limit(max(1, min(int(limit or 200), 500)))
                return [self._to_provider_config_summary(item) for item in session.exec(stmt).all()]
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

    def get_provider_config(self, config_id: int) -> dict[str, Any]:
        try:
            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxProviderConfigModel, config_id)
                if not model:
                    raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
                return self._to_provider_config_detail(model)
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

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
        try:
            model = MailboxProviderConfigModel(
                name=clean_name,
                provider=provider,
                enabled=bool(enabled),
                description=str(description or "").strip(),
                proxy=_encrypt_string_maybe(proxy),
                extra_json=_encrypt_json_maybe(dict(extra or {})),
            )
            with Session(get_mailbox_service_engine()) as session:
                session.add(model)
                session.commit()
                session.refresh(model)
                return self._to_provider_config_detail(model)
        except CryptoConfigError as exc:
            _raise_storage_write_error(exc)
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
            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxProviderConfigModel, config_id)
                if not model:
                    raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
                model.name = clean_name
                model.provider = provider
                model.enabled = bool(enabled)
                model.description = str(description or "").strip()
                model.proxy = _encrypt_string_maybe(proxy)
                model.extra_json = _encrypt_json_maybe(dict(extra or {}))
                model.updated_at = _utcnow()
                session.add(model)
                session.commit()
                session.refresh(model)
                return self._to_provider_config_detail(model)
        except CryptoConfigError as exc:
            _raise_storage_write_error(exc)
        except IntegrityError as exc:
            raise MailboxServiceError("PROVIDER_CONFIG_NAME_EXISTS", f"provider 配置名称已存在: {clean_name}") from exc

    def delete_provider_config(self, config_id: int) -> None:
        with Session(get_mailbox_service_engine()) as session:
            model = session.get(MailboxProviderConfigModel, config_id)
            if not model:
                raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
            session.delete(model)
            session.commit()

    def validate_saved_provider_config(self, config_id: int) -> dict[str, Any]:
        try:
            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxProviderConfigModel, config_id)
                if not model:
                    raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
                provider = model.provider
                extra = dict(_decrypt_json_maybe(model.extra_json, {}))
                proxy = _decrypt_string_maybe(model.proxy, default="") or None

            try:
                result = self.validate_provider_config(provider=provider, extra=extra, proxy=proxy)
                ok = True
                message = "ok"
            except Exception as exc:
                result = {"ok": False, "provider": provider}
                ok = False
                message = redact_sensitive_text(str(exc))

            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxProviderConfigModel, config_id)
                if not model:
                    raise MailboxServiceError("PROVIDER_CONFIG_NOT_FOUND", f"未找到 provider 配置: {config_id}")
                model.last_validated_at = _utcnow()
                model.last_validation_ok = ok
                model.last_validation_message = redact_sensitive_text(message)
                model.updated_at = _utcnow()
                session.add(model)
                session.commit()
                session.refresh(model)

            response = self._to_provider_config_detail(model)
            response["validation"] = {
                "ok": ok,
                "message": redact_sensitive_text(message),
                "provider": result.get("provider", provider),
            }
            return response
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

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
        try:
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
                merged_extra = dict(_decrypt_json_maybe(source_config.extra_json, {}))
                merged_extra.update(resolved_extra)
                resolved_extra = merged_extra
                if resolved_proxy is None:
                    resolved_proxy = _decrypt_string_maybe(source_config.proxy, default="") or None

            if not resolved_provider:
                raise MailboxServiceError("PROVIDER_REQUIRED", "必须提供 provider，或通过 config_id/config_name 指定保存配置")

            self.validate_provider(resolved_provider)
            return {
                "provider": resolved_provider,
                "extra": resolved_extra,
                "proxy": resolved_proxy,
                "config": self._to_provider_config_summary(source_config) if source_config else None,
            }
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

    def list_recent_sessions(
        self,
        *,
        q: str = "",
        provider: str | None = None,
        state: str | None = None,
        result: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        try:
            with Session(get_mailbox_service_engine()) as session:
                stmt = select(MailboxSessionModel)
                keyword = str(q or "").strip()
                if keyword:
                    stmt = stmt.where(
                        or_(
                            MailboxSessionModel.session_id.contains(keyword),
                            MailboxSessionModel.email.contains(keyword),
                            MailboxSessionModel.purpose.contains(keyword),
                        )
                    )
                if str(provider or "").strip():
                    stmt = stmt.where(MailboxSessionModel.provider == str(provider).strip())
                if str(state or "").strip():
                    stmt = stmt.where(MailboxSessionModel.state == str(state).strip())
                if str(result or "").strip():
                    stmt = stmt.where(MailboxSessionModel.result == str(result).strip())
                stmt = stmt.order_by(
                    MailboxSessionModel.created_at.desc(),
                    MailboxSessionModel.session_id.desc(),
                )
                stmt = stmt.offset(max(0, int(offset or 0))).limit(max(1, min(int(limit or 50), 200)))
                return [self._to_session_summary(item) for item in session.exec(stmt).all()]
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

    def acquire_session(
        self,
        *,
        provider: str,
        session_mode: str = SESSION_MODE_MANAGED,
        extra: Optional[dict[str, Any]] = None,
        proxy: Optional[str] = None,
        purpose: str = "generic",
        account_override: Any = None,
        lease_seconds: int = 900,
        requested_email: str = "",
    ) -> MailboxLease:
        self.validate_provider(provider)
        resolved_session_mode = self.normalize_session_mode(provider, session_mode)
        if resolved_session_mode == SESSION_MODE_CREDENTIALED and account_override is None:
            raise MailboxServiceError("CREDENTIAL_REQUIRED", "credentialed 会话模式必须提供 existing_account")
        extra = dict(extra or {})
        # 前置必填字段校验：消费 PROVIDER_SESSION_METADATA[*]["required_fields_by_mode"]，
        # 在 _create_local_mailbox 之前就把"配置缺失"识别为 422，避免到了底层 provider
        # 才抛裸 RuntimeError 被 FastAPI 渲染成 500。
        self._check_required_fields(
            provider=provider,
            session_mode=resolved_session_mode,
            extra=extra,
            account_override=account_override,
        )
        mailbox = self._create_local_mailbox(provider=provider, extra=extra, proxy=proxy)

        if account_override is None:
            account = mailbox.get_email(requested_email=requested_email)
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
            session_mode=resolved_session_mode,
            email=account.email,
            account_id=str(account.account_id or ""),
            state="leased",
            expires_at=expires_at,
            before_ids=before_ids,
            provider_meta=provider_meta,
        )
        try:
            with Session(get_mailbox_service_engine()) as session:
                model = MailboxSessionModel(
                    session_id=lease.session_id,
                    lease_token="",
                    lease_token_hash=hash_token(lease.lease_token),
                    provider=provider,
                    session_mode=resolved_session_mode,
                    email=lease.email,
                    account_id=lease.account_id,
                    purpose=str(purpose or "generic"),
                    state=lease.state,
                    proxy=_encrypt_string_maybe(proxy),
                    config_json=_encrypt_json_maybe(extra),
                    account_extra_json=_encrypt_json_maybe(account.extra or {}),
                    before_ids_json=_json_dumps(before_ids),
                    provider_meta_json=_encrypt_json_maybe(provider_meta),
                    expires_at=expires_at,
                )
                session.add(model)
                session.commit()
        except CryptoConfigError as exc:
            _raise_storage_write_error(exc)

        self._record_event(
            lease.session_id,
            "created",
            {
                "email": lease.email,
                "provider": provider,
                "session_mode": resolved_session_mode,
                "provider_meta": redact_structure(provider_meta),
            },
        )
        return lease

    def get_session(self, session_id: str) -> MailboxLease:
        try:
            with Session(get_mailbox_service_engine()) as session:
                model = session.get(MailboxSessionModel, session_id)
                if not model:
                    raise MailboxServiceError("SESSION_NOT_FOUND", f"未找到会话: {session_id}")
                self._expire_if_needed(session, model)
                return self._to_lease(model)
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

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
        with Session(get_mailbox_service_engine()) as session:
            model = self._get_session_model(session, session_id, lease_token)
            model.state = "polling"
            model.updated_at = _utcnow()
            session.add(model)
            session.commit()

        try:
            model = self.get_session_model(session_id, lease_token)
            mailbox, account, snapshot_ids = self._hydrate_runtime(model)
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

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
            message = redact_sensitive_text(str(exc))
            with Session(get_mailbox_service_engine()) as session:
                model = self._get_session_model(session, session_id, lease_token)
                model.state = "failed"
                model.error_code = error_code
                model.error_message = message
                model.updated_at = _utcnow()
                session.add(model)
                session.commit()
            self._record_event(session_id, "poll_failed", {"error_code": error_code, "message": message})
            return MailboxPollResult(status="failed", message=message, error_code=error_code)

        with Session(get_mailbox_service_engine()) as session:
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
        try:
            with Session(get_mailbox_service_engine()) as session:
                model = self._get_session_model(session, session_id, lease_token)
                if model.completed_at:
                    return self._to_lease(model, lease_token=lease_token)

            if str(result or "").lower() == "success":
                try:
                    mailbox, account, _ = self._hydrate_runtime(self.get_session_model(session_id, lease_token))
                    self._prepare_selected_account(mailbox, account.email)
                    if hasattr(mailbox, "remove_used_account"):
                        mailbox.remove_used_account()
                except Exception as exc:
                    self._record_event(session_id, "cleanup_failed", {"message": redact_sensitive_text(str(exc))})

            safe_reason = redact_sensitive_text(reason)
            with Session(get_mailbox_service_engine()) as session:
                model = self._get_session_model(session, session_id, lease_token)
                model.result = str(result or "").strip().lower()
                model.state = "completed"
                model.completed_at = _utcnow()
                model.updated_at = _utcnow()
                if safe_reason:
                    model.error_message = safe_reason
                session.add(model)
                session.commit()
                lease = self._to_lease(model, lease_token=lease_token)
            self._record_event(session_id, "completed", {"result": result, "reason": safe_reason})
            return lease
        except CryptoConfigError as exc:
            _raise_storage_read_error(exc)

    def get_session_model(self, session_id: str, lease_token: str) -> MailboxSessionModel:
        with Session(get_mailbox_service_engine()) as session:
            model = self._get_session_model(session, session_id, lease_token)
            session.expunge(model)
            return model

    def _hydrate_runtime(self, model: MailboxSessionModel):
        from core.base_mailbox import MailboxAccount

        extra = _decrypt_json_maybe(model.config_json, {})
        account_extra = _decrypt_json_maybe(model.account_extra_json, {})
        before_ids = set(_json_loads(model.before_ids_json, []))
        proxy = _decrypt_string_maybe(model.proxy, default="") or None
        mailbox = self._create_local_mailbox(provider=model.provider, extra=extra, proxy=proxy)
        account = MailboxAccount(
            email=model.email,
            account_id=model.account_id or "",
            extra=account_extra or None,
        )
        if account.extra:
            self._prepare_known_account(mailbox, account)
        return mailbox, account, before_ids

    def _create_local_mailbox(self, *, provider: str, extra: dict[str, Any], proxy: Optional[str]):
        from core.base_mailbox import create_local_mailbox

        return create_local_mailbox(provider=provider, extra=extra, proxy=proxy)

    def _check_required_fields(
        self,
        *,
        provider: str,
        session_mode: str,
        extra: dict[str, Any],
        account_override: Any,
    ) -> None:
        """根据 PROVIDER_SESSION_METADATA[<provider>]['required_fields_by_mode']
        做前置校验。任意必填字段为空（None / 空串 / 空集合）即抛
        ``ProviderConfigIncompleteError``。

        字段路径形态：
        - ``some_field``：从 ``extra`` 取值
        - ``existing_account.email``：从 ``account_override`` 直接取属性
        - ``existing_account.credentials.client_id``：从 ``account_override.extra``
          或 ``account_override.credentials`` 嵌套取值
        """
        metadata = PROVIDER_SESSION_METADATA.get(provider) or {}
        required_by_mode = metadata.get("required_fields_by_mode") or {}
        required = list(required_by_mode.get(session_mode) or [])
        if not required:
            return

        missing: list[str] = []
        for field in required:
            if field.startswith("existing_account."):
                if not self._existing_account_field_present(account_override, field):
                    missing.append(field)
                continue
            value = extra.get(field)
            if value is None or value == "" or value == [] or value == {}:
                missing.append(field)

        if missing:
            raise ProviderConfigIncompleteError(
                (
                    f"provider={provider} session_mode={session_mode} 缺少必填字段: "
                    f"{', '.join(missing)}。请在 admin UI 完善 provider 配置或在请求里"
                    "通过 config_name/config_id 引用已保存的配置。"
                ),
                missing_fields=missing,
            )

    @staticmethod
    def _existing_account_field_present(account_override: Any, dotted: str) -> bool:
        """检查 ``existing_account.<path>`` 这种 dotted 字段是否在 account_override 上有非空值。

        解析顺序（按声明路径 ``existing_account.<head>.<...rest>``）：

        1. **属性路径**：``getattr(account_override, head)`` 若拿到非空值，就沿
           ``rest`` 继续走（dict 用 ``.get``、对象用 ``getattr``）。覆盖 ``email``
           / ``account_id`` 等直接挂在 ``MailboxAccount`` 上的字段。

        2. **extra 嵌套路径**：head 在属性上为空时，回退到
           ``account_override.extra[head]``，再沿 ``rest`` 继续。覆盖那种"子结构
           被原样塞进 extra"的形态。

        3. **extra 摊平路径**（本次新增）：如果嵌套路径仍空且 ``rest`` 至少有一段，
           就尝试把 ``rest[0]`` 直接当 ``extra`` 顶层 key 查找。这一条对应
           ``api/mailbox_service.py:_build_account_override_from_existing_account``
           的转换约定 -- 它把 ``ExistingAccount.credentials.client_id`` 摊平到
           ``MailboxAccount.extra["client_id"]``，所以声明路径
           ``existing_account.credentials.client_id`` 必须能在摊平后的 extra 顶层
           解析到 ``client_id``。命中即返回 True，不再继续 rest 遍历。

        三层退化设计的目的：让 ``PROVIDER_SESSION_METADATA`` 的字段路径声明保持
        与 Pydantic 请求 schema（``ExistingAccount.credentials.X``）一致，同时
        兼容下游 ``_build_account_override`` 已固化多年的"摊平 credentials 到
        extra 顶层"约定，无需联动改 metadata 或下游业务代码。
        """
        if account_override is None:
            return False
        # path 例：existing_account.email / existing_account.credentials.client_id
        parts = dotted.split(".")[1:]  # 去掉 "existing_account" 前缀
        if not parts:
            return False
        head, *rest = parts
        cursor: Any = getattr(account_override, head, None)
        # 第 2 层：head 不在属性上时回退到 extra[head]
        if cursor in (None, "", [], {}):
            extra = getattr(account_override, "extra", None) or {}
            extra_dict = extra if isinstance(extra, dict) else {}
            cursor = extra_dict.get(head)
            # 第 3 层：head 是 "credentials" 这种摊平容器名 -- 嵌套查不到时
            # 直接用 rest[0] 到 extra 顶层找，对应 _build_account_override
            # 的摊平约定（credentials.X → extra["X"]）。命中即结束，
            # 不再继续 rest 遍历，避免误把摊平值再当 dict 套一层。
            if cursor in (None, "", [], {}) and rest:
                flat_value = extra_dict.get(rest[0])
                if flat_value not in (None, "", [], {}):
                    return True
        for key in rest:
            if cursor is None:
                return False
            if isinstance(cursor, dict):
                cursor = cursor.get(key)
            else:
                cursor = getattr(cursor, key, None)
        return cursor not in (None, "", [], {})

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

    def _prepare_dynamic_applemail_account(self, mailbox, account) -> None:
        accounts = getattr(mailbox, "_accounts", None)
        extra = dict(getattr(account, "extra", None) or {})
        email = str(getattr(account, "email", "") or "").strip()
        client_id = str(extra.get("client_id") or extra.get("mail_client_id") or "").strip()
        refresh_token = str(extra.get("refresh_token") or extra.get("mail_refresh_token") or "").strip()
        if not isinstance(accounts, list) or not email or not client_id or not refresh_token:
            return

        # applemail 已知邮箱接管模式下，允许业务端直接补齐最小凭据上下文，
        # 避免必须预先在后台保存整份账号池配置才能拉取当前邮箱验证码。
        dynamic_account = {
            "email": email,
            "password": str(extra.get("password") or "unused").strip(),
            "client_id": client_id,
            "refresh_token": refresh_token,
            "raw": f"{email}----{str(extra.get('password') or 'unused').strip()}----{client_id}----{refresh_token}",
        }
        for item in accounts:
            if str((item or {}).get("email", "")).strip().lower() == email.lower():
                item.update(dynamic_account)
                dynamic_account = item
                break
        else:
            accounts.append(dynamic_account)

        try:
            mailbox._selected = dynamic_account
        except Exception:
            pass

    def _prepare_known_account(self, mailbox, account) -> None:
        self._prepare_selected_account(mailbox, account.email)
        if not getattr(mailbox, "_selected", None):
            self._prepare_dynamic_applemail_account(mailbox, account)

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
        preserve_existing_mail = bool(dict(getattr(account, "extra", None) or {}).get("preserve_existing_mail"))
        if selected and hasattr(mailbox, "_clear_mailbox") and not preserve_existing_mail:
            try:
                mailbox._clear_mailbox(selected)
            except Exception:
                pass

    def _record_event(self, session_id: str, event_type: str, detail: dict[str, Any]) -> None:
        with Session(get_mailbox_service_engine()) as session:
            session.add(
                MailboxSessionEventModel(
                    session_id=session_id,
                    event_type=event_type,
                    detail_json=_json_dumps(redact_structure(detail)),
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
        if not self._lease_token_matches(model, lease_token):
            raise MailboxServiceError("INVALID_LEASE", "邮箱会话租约无效")
        self._expire_if_needed(session, model)
        return model

    def _lease_token_matches(self, model: MailboxSessionModel, lease_token: str) -> bool:
        candidate = str(lease_token or "")
        if not candidate:
            return False
        stored_hash = str(model.lease_token_hash or "")
        stored_plain = str(model.lease_token or "")
        return (
            (stored_hash and secrets.compare_digest(stored_hash, hash_token(candidate)))
            or (stored_plain and secrets.compare_digest(stored_plain, candidate))
        )

    def _to_lease(self, model: MailboxSessionModel, lease_token: str = "") -> MailboxLease:
        provider_meta = dict(_decrypt_json_maybe(model.provider_meta_json, {}))
        before_ids = [str(item) for item in _json_loads(model.before_ids_json, []) if str(item)]
        return MailboxLease(
            session_id=model.session_id,
            lease_token=str(lease_token or ""),
            provider=model.provider,
            session_mode=str(model.session_mode or SESSION_MODE_MANAGED),
            email=model.email,
            account_id=model.account_id or "",
            state=model.state,
            expires_at=_ensure_utc(model.expires_at),
            before_ids=before_ids,
            provider_meta=provider_meta,
        )

    def _to_provider_config_summary(self, model: MailboxProviderConfigModel | None) -> dict[str, Any] | None:
        if model is None:
            return None
        proxy = _decrypt_string_maybe(model.proxy, default="")
        profile = self.provider_session_profile(model.provider)
        return {
            "id": model.id,
            "name": model.name,
            "provider": model.provider,
            "enabled": bool(model.enabled),
            "description": model.description,
            "proxy_configured": bool(proxy),
            "proxy_masked": mask_proxy(proxy) if proxy else "",
            "supported_session_modes": profile["supported_session_modes"],
            "default_session_mode": profile["default_session_mode"],
            "capabilities": profile["capabilities"],
            "required_fields_by_mode": profile["required_fields_by_mode"],
            "notes": profile["notes"],
            "created_at": _ensure_utc(model.created_at).isoformat(),
            "updated_at": _ensure_utc(model.updated_at).isoformat(),
            "last_validated_at": _ensure_utc(model.last_validated_at).isoformat() if model.last_validated_at else None,
            "last_validation_ok": model.last_validation_ok,
            "last_validation_message": redact_sensitive_text(model.last_validation_message),
        }

    def _to_provider_config_detail(self, model: MailboxProviderConfigModel | None) -> dict[str, Any] | None:
        if model is None:
            return None
        payload = self._to_provider_config_summary(model) or {}
        payload.update(
            {
                "proxy": _decrypt_string_maybe(model.proxy, default=""),
                "extra": dict(_decrypt_json_maybe(model.extra_json, {})),
            }
        )
        return payload

    def _to_provider_config(self, model: MailboxProviderConfigModel | None) -> dict[str, Any] | None:
        return self._to_provider_config_detail(model)

    def _to_session_summary(self, model: MailboxSessionModel) -> dict[str, Any]:
        return {
            "session_id": model.session_id,
            "provider": model.provider,
            "session_mode": str(model.session_mode or SESSION_MODE_MANAGED),
            "email": model.email,
            "purpose": model.purpose,
            "state": model.state,
            "result": model.result,
            "error_code": model.error_code,
            "error_message": redact_sensitive_text(model.error_message),
            "provider_meta": redact_structure(_decrypt_json_maybe(model.provider_meta_json, {})),
            "proxy_masked": mask_proxy(_decrypt_string_maybe(model.proxy, default="")),
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
        with Session(get_mailbox_service_engine()) as session:
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
mailbox_service_engine = get_mailbox_service_engine()


def init_mailbox_service_db() -> None:
    global mailbox_service_engine
    mailbox_service_engine = get_mailbox_service_engine()
    mailbox_service.init_db()
