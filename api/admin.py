from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.security import verify_api_key
from services.mailbox_service import MailboxServiceError, mailbox_service


router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(verify_api_key)],
)


class ProviderConfigBody(BaseModel):
    name: str
    provider: str
    enabled: bool = True
    description: str = ""
    proxy: str | None = None
    extra: dict = Field(default_factory=dict)


def _raise_http(exc: MailboxServiceError):
    raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})


@router.get("/provider-catalog")
def admin_provider_catalog():
    return {"providers": mailbox_service.provider_catalog()}


@router.get("/provider-configs")
def list_provider_configs():
    return {"items": mailbox_service.list_provider_configs()}


@router.post("/provider-configs")
def create_provider_config(body: ProviderConfigBody):
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
def get_provider_config(config_id: int):
    try:
        return mailbox_service.get_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)


@router.put("/provider-configs/{config_id}")
def update_provider_config(config_id: int, body: ProviderConfigBody):
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
def delete_provider_config(config_id: int):
    try:
        mailbox_service.delete_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)
    return {"ok": True}


@router.post("/provider-configs/{config_id}/validate")
def validate_saved_provider_config(config_id: int):
    try:
        return mailbox_service.validate_saved_provider_config(config_id)
    except MailboxServiceError as exc:
        _raise_http(exc)
    except Exception as exc:
        raise HTTPException(status_code=400, detail={"code": "INVALID_PROVIDER_CONFIG", "message": str(exc)})


@router.get("/recent-sessions")
def recent_sessions(limit: int = Query(default=50, ge=1, le=200)):
    return {"items": mailbox_service.list_recent_sessions(limit=limit)}
