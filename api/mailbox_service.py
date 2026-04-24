from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.security import verify_api_key
from services.mailbox_service import (
    MailboxLease,
    MailboxServiceError,
    SESSION_MODE_CREDENTIALED,
    SESSION_MODE_MANAGED,
    mailbox_service,
)


router = APIRouter(
    prefix="/mailbox-service",
    tags=["mailbox-service"],
    dependencies=[Depends(verify_api_key)],
)


class BaseMailboxSessionRequest(BaseModel):
    provider: str | None = None
    config_id: int | None = None
    config_name: str | None = None
    purpose: str = "generic"
    session_mode: str | None = None
    proxy: str | None = None
    extra: dict = Field(default_factory=dict)
    lease_seconds: int = 900


class AccountCredentials(BaseModel):
    client_id: str = ""
    refresh_token: str = ""
    password: str = ""


class ExistingAccount(BaseModel):
    email: str
    account_id: str = ""
    extra: dict = Field(default_factory=dict)
    preserve_existing_mail: bool = True
    credentials: AccountCredentials | None = None


class ManagedMailboxSessionRequest(BaseMailboxSessionRequest):
    pass


class CredentialedMailboxSessionRequest(BaseMailboxSessionRequest):
    existing_account: ExistingAccount


class CreateMailboxSessionRequest(BaseMailboxSessionRequest):
    email: str | None = None
    account_id: str | None = None
    account_extra: dict | None = None
    existing_account: ExistingAccount | None = None


class PollMailboxCodeRequest(BaseModel):
    lease_token: str
    timeout_seconds: int = 120
    keyword: str = ""
    code_pattern: str | None = None
    otp_sent_at: float | None = None
    exclude_codes: list[str] = Field(default_factory=list)
    before_ids: list[str] = Field(default_factory=list)


class CompleteMailboxSessionRequest(BaseModel):
    lease_token: str
    result: str
    reason: str = ""


class ValidateMailboxProviderRequest(BaseModel):
    extra: dict = Field(default_factory=dict)
    proxy: str | None = None


def _raise_http(exc: MailboxServiceError):
    status_code = 400
    if exc.code.endswith("_NOT_FOUND"):
        status_code = 404
    elif exc.code.endswith("_EXISTS"):
        status_code = 409
    elif exc.code in {"INVALID_LEASE"}:
        status_code = 401
    elif exc.code in {"LEASE_EXPIRED"}:
        status_code = 410
    elif exc.code in {"ENCRYPTION_NOT_CONFIGURED"}:
        status_code = 503
    raise HTTPException(status_code=status_code, detail={"code": exc.code, "message": exc.message})


def _coerce_session_mode(provider: str, session_mode: str | None) -> str:
    return mailbox_service.normalize_session_mode(provider, session_mode)


def _build_account_override_from_existing_account(existing_account: ExistingAccount):
    from core.base_mailbox import MailboxAccount

    extra = dict(existing_account.extra or {})
    extra["preserve_existing_mail"] = bool(existing_account.preserve_existing_mail)
    if existing_account.credentials is not None:
        if existing_account.credentials.client_id:
            extra["client_id"] = existing_account.credentials.client_id
        if existing_account.credentials.refresh_token:
            extra["refresh_token"] = existing_account.credentials.refresh_token
        if existing_account.credentials.password:
            extra["password"] = existing_account.credentials.password
    return MailboxAccount(
        email=str(existing_account.email or "").strip(),
        account_id=str(existing_account.account_id or "").strip(),
        extra=extra,
    )


def _build_account_override_from_legacy_fields(
    *,
    email: str | None,
    account_id: str | None,
    account_extra: dict | None,
):
    if not (email or account_id or account_extra):
        return None
    from core.base_mailbox import MailboxAccount

    return MailboxAccount(
        email=str(email or "").strip(),
        account_id=str(account_id or "").strip(),
        extra=dict(account_extra or {}),
    )


def _validate_credentialed_account(provider: str, account_override: Any) -> None:
    email = str(getattr(account_override, "email", "") or "").strip()
    if not email:
        raise MailboxServiceError("EMAIL_REQUIRED", "credentialed 会话必须提供邮箱")

    extra = dict(getattr(account_override, "extra", None) or {})
    if provider == "applemail":
        client_id = str(extra.get("client_id") or "").strip()
        refresh_token = str(extra.get("refresh_token") or "").strip()
        if not client_id or not refresh_token:
            raise MailboxServiceError(
                "INVALID_EXISTING_ACCOUNT",
                "applemail credentialed 会话必须提供 client_id 和 refresh_token",
            )


def _response_from_lease(lease: MailboxLease, runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {
        "session_id": lease.session_id,
        "lease_token": lease.lease_token,
        "provider": lease.provider,
        "session_mode": lease.session_mode,
        "email": lease.email,
        "account_id": lease.account_id,
        "state": lease.state,
        "expires_at": lease.expires_at,
        "before_ids": lease.before_ids,
        "provider_meta": lease.provider_meta,
    }
    if runtime is not None:
        payload["provider_config"] = runtime.get("config")
    return payload


@router.get("/health")
def mailbox_service_health():
    return mailbox_service.health()


@router.get("/providers")
def list_mailbox_service_providers():
    return {"providers": mailbox_service.list_providers()}


@router.post("/providers/{provider}/validate-config")
def validate_mailbox_service_provider(provider: str, body: ValidateMailboxProviderRequest):
    try:
        result = mailbox_service.validate_provider_config(
            provider=provider,
            extra=body.extra,
            proxy=body.proxy,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"code": "INVALID_PROVIDER_CONFIG", "message": str(exc)})
    return result


@router.post("/sessions")
def create_mailbox_session(body: CreateMailboxSessionRequest):
    try:
        runtime = mailbox_service.resolve_provider_request(
            provider=body.provider,
            extra=body.extra,
            proxy=body.proxy,
            config_id=body.config_id,
            config_name=body.config_name,
        )
        account_override = None
        requested_mode = str(body.session_mode or "").strip().lower() or None
        if body.existing_account is not None:
            account_override = _build_account_override_from_existing_account(body.existing_account)
            requested_mode = requested_mode or SESSION_MODE_CREDENTIALED
        else:
            account_override = _build_account_override_from_legacy_fields(
                email=body.email,
                account_id=body.account_id,
                account_extra=body.account_extra,
            )
            if account_override is not None:
                requested_mode = requested_mode or SESSION_MODE_CREDENTIALED

        session_mode = _coerce_session_mode(runtime["provider"], requested_mode)
        if body.existing_account is not None and session_mode != SESSION_MODE_CREDENTIALED:
            raise MailboxServiceError("INVALID_SESSION_REQUEST", "existing_account 仅支持 credentialed 会话")
        if session_mode == SESSION_MODE_CREDENTIALED:
            if account_override is None:
                raise MailboxServiceError("CREDENTIAL_REQUIRED", "credentialed 会话模式必须提供 existing_account")
            _validate_credentialed_account(runtime["provider"], account_override)
        else:
            account_override = None

        lease = mailbox_service.acquire_session(
            provider=runtime["provider"],
            session_mode=session_mode,
            extra=runtime["extra"],
            proxy=runtime["proxy"],
            purpose=body.purpose,
            account_override=account_override,
            lease_seconds=body.lease_seconds,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    return _response_from_lease(lease, runtime)


@router.post("/managed-sessions")
def create_managed_mailbox_session(body: ManagedMailboxSessionRequest):
    try:
        runtime = mailbox_service.resolve_provider_request(
            provider=body.provider,
            extra=body.extra,
            proxy=body.proxy,
            config_id=body.config_id,
            config_name=body.config_name,
        )
        lease = mailbox_service.acquire_session(
            provider=runtime["provider"],
            session_mode=_coerce_session_mode(runtime["provider"], SESSION_MODE_MANAGED),
            extra=runtime["extra"],
            proxy=runtime["proxy"],
            purpose=body.purpose,
            lease_seconds=body.lease_seconds,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    return _response_from_lease(lease, runtime)


@router.post("/credentialed-sessions")
def create_credentialed_mailbox_session(body: CredentialedMailboxSessionRequest):
    try:
        runtime = mailbox_service.resolve_provider_request(
            provider=body.provider,
            extra=body.extra,
            proxy=body.proxy,
            config_id=body.config_id,
            config_name=body.config_name,
        )
        account_override = _build_account_override_from_existing_account(body.existing_account)
        _validate_credentialed_account(runtime["provider"], account_override)
        lease = mailbox_service.acquire_session(
            provider=runtime["provider"],
            session_mode=_coerce_session_mode(runtime["provider"], SESSION_MODE_CREDENTIALED),
            extra=runtime["extra"],
            proxy=runtime["proxy"],
            purpose=body.purpose,
            account_override=account_override,
            lease_seconds=body.lease_seconds,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    return _response_from_lease(lease, runtime)


@router.get("/sessions/{session_id}")
def get_mailbox_session(session_id: str):
    try:
        lease = mailbox_service.get_session(session_id)
    except MailboxServiceError as exc:
        _raise_http(exc)
    return {
        "session_id": lease.session_id,
        "provider": lease.provider,
        "session_mode": lease.session_mode,
        "email": lease.email,
        "account_id": lease.account_id,
        "state": lease.state,
        "expires_at": lease.expires_at,
        "before_ids": lease.before_ids,
        "provider_meta": lease.provider_meta,
    }


@router.post("/sessions/{session_id}/poll-code")
def poll_mailbox_code(session_id: str, body: PollMailboxCodeRequest):
    try:
        result = mailbox_service.poll_code(
            session_id=session_id,
            lease_token=body.lease_token,
            timeout_seconds=body.timeout_seconds,
            keyword=body.keyword,
            code_pattern=body.code_pattern,
            otp_sent_at=body.otp_sent_at,
            exclude_codes=set(body.exclude_codes),
            before_ids=set(body.before_ids),
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    return {
        "status": result.status,
        "code": result.code,
        "message": result.message,
        "matched_mailbox": result.matched_mailbox,
        "error_code": result.error_code,
    }


@router.post("/sessions/{session_id}/complete")
def complete_mailbox_session(session_id: str, body: CompleteMailboxSessionRequest):
    try:
        lease = mailbox_service.complete_session(
            session_id=session_id,
            lease_token=body.lease_token,
            result=body.result,
            reason=body.reason,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)
    return {
        "session_id": lease.session_id,
        "provider": lease.provider,
        "session_mode": lease.session_mode,
        "email": lease.email,
        "state": lease.state,
        "expires_at": lease.expires_at,
    }
