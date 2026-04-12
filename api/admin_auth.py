from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from api.security import (
    AdminAccessContext,
    clear_admin_auth_cookies,
    client_ip_for_request,
    set_admin_auth_cookies,
    user_agent_for_request,
    verify_admin_access,
    verify_admin_write_access,
)
from services.admin_auth_service import AdminAuthError, admin_auth_service


router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


class AdminLoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=4096)


def _raise_http(exc: AdminAuthError):
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == status.HTTP_401_UNAUTHORIZED else None
    raise HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message},
        headers=headers,
    )


@router.post("/login")
def admin_login(body: AdminLoginBody, request: Request, response: Response):
    try:
        session_token, csrf_token, expires_at = admin_auth_service.login(
            username=body.username,
            password=body.password,
            client_ip=client_ip_for_request(request),
            user_agent=user_agent_for_request(request),
        )
    except AdminAuthError as exc:
        _raise_http(exc)
    max_age = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
    set_admin_auth_cookies(
        response,
        request,
        session_token=session_token,
        csrf_token=csrf_token,
        max_age=max_age,
    )
    return {
        "ok": True,
        "username": body.username,
        "expires_at": expires_at.isoformat(),
        "csrf_cookie_name": admin_auth_service.CSRF_COOKIE_NAME,
    }


@router.get("/me")
def admin_me(access: AdminAccessContext = Depends(verify_admin_access)):
    return {
        "ok": True,
        "auth_mode": access.auth_mode,
        "username": access.username,
        "expires_at": access.session.expires_at.isoformat() if access.session else None,
        "csrf_cookie_name": admin_auth_service.CSRF_COOKIE_NAME,
    }


@router.post("/logout")
def admin_logout(
    request: Request,
    response: Response,
    access: AdminAccessContext = Depends(verify_admin_write_access),
):
    if access.auth_mode == "session" and access.session_token:
        admin_auth_service.logout(
            session_token=access.session_token,
            client_ip=client_ip_for_request(request),
            user_agent=user_agent_for_request(request),
        )
    clear_admin_auth_cookies(response, request)
    return {"ok": True}
