from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.security import AdminAccessContext, verify_admin_access, verify_admin_write_access
from services.mailbox_service import MailboxServiceError, mailbox_service


router = APIRouter(prefix="/admin", tags=["admin"])


class ProviderConfigBody(BaseModel):
    name: str
    provider: str
    enabled: bool = True
    description: str = ""
    proxy: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


def _status_for_error(exc: MailboxServiceError) -> int:
    if exc.code in {"PROVIDER_CONFIG_NOT_FOUND", "SESSION_NOT_FOUND"}:
        return 404
    if exc.code in {"INVALID_LEASE", "UNAUTHORIZED"}:
        return 401
    if exc.code == "ENCRYPTION_NOT_CONFIGURED":
        return 503
    return 400


def _raise_http(exc: MailboxServiceError):
    raise HTTPException(status_code=_status_for_error(exc), detail={"code": exc.code, "message": exc.message})


@router.get("/provider-catalog")
def admin_provider_catalog(_access: AdminAccessContext = Depends(verify_admin_access)):
    return {"providers": mailbox_service.provider_catalog()}


@router.get("/provider-configs")
def list_provider_configs(
    q: str = Query(default=""),
    provider: str | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _access: AdminAccessContext = Depends(verify_admin_access),
):
    items = mailbox_service.list_provider_configs(
        q=q,
        provider=provider,
        enabled=enabled,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": len(items)}


@router.post("/provider-configs")
def create_provider_config(
    body: ProviderConfigBody,
    _access: AdminAccessContext = Depends(verify_admin_write_access),
):
    try:
        return mailbox_service.create_provider_config(
            name=body.name,
            provider=body.provider,
            enabled=body.enabled,
            description=body.description,
            proxy=body.proxy,
            extra=body.extra,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)


@router.get("/provider-configs/{config_id}")
def get_provider_config(
    config_id: int,
    _access: AdminAccessContext = Depends(verify_admin_access),
):
    try:
        return mailbox_service.get_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)


@router.put("/provider-configs/{config_id}")
def update_provider_config(
    config_id: int,
    body: ProviderConfigBody,
    _access: AdminAccessContext = Depends(verify_admin_write_access),
):
    try:
        return mailbox_service.update_provider_config(
            config_id,
            name=body.name,
            provider=body.provider,
            enabled=body.enabled,
            description=body.description,
            proxy=body.proxy,
            extra=body.extra,
        )
    except MailboxServiceError as exc:
        _raise_http(exc)


@router.delete("/provider-configs/{config_id}")
def delete_provider_config(
    config_id: int,
    _access: AdminAccessContext = Depends(verify_admin_write_access),
):
    try:
        mailbox_service.delete_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)
    return {"ok": True}


@router.post("/provider-configs/{config_id}/validate")
def validate_saved_provider_config(
    config_id: int,
    _access: AdminAccessContext = Depends(verify_admin_write_access),
):
    try:
        return mailbox_service.validate_saved_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"code": "INVALID_PROVIDER_CONFIG", "message": str(exc)})


@router.get("/recent-sessions")
def recent_sessions(
    q: str = Query(default=""),
    provider: str | None = Query(default=None),
    state: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _access: AdminAccessContext = Depends(verify_admin_access),
):
    items = mailbox_service.list_recent_sessions(
        q=q,
        provider=provider,
        state=state,
        limit=limit,
        offset=offset,
    )
    return {"items": items, "total": len(items)}
