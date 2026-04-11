from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel

from api.security import (
    AdminAccessContext,
    clear_admin_auth_cookies,
    client_ip_for_request,
    set_admin_auth_cookies,
    user_agent_for_request,
    verify_admin_access,
    verify_admin_session,
)
from services.admin_auth_service import AdminAuthError, admin_auth_service

router = APIRouter(prefix="/admin/auth", tags=["admin-auth"])


class AdminLoginBody(BaseModel):
    username: str
    password: str


def _raise_admin_http(exc: AdminAuthError) -> None:
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
    raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}, headers=headers)


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
        _raise_admin_http(exc)

    now = datetime.now(timezone.utc)
    max_age = max(60, int((expires_at - now).total_seconds()))
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
        "auth_mode": "session",
        "expires_at": expires_at.isoformat(),
    }


@router.get("/me")
def admin_me(access: AdminAccessContext = Depends(verify_admin_access)):
    if access.auth_mode == "api_key":
        return {
            "ok": True,
            "auth_mode": "api_key",
            "username": access.username,
            "expires_at": None,
        }

    return {
        "ok": True,
        "auth_mode": "session",
        "username": access.username,
        "expires_at": access.session.expires_at.isoformat() if access.session else None,
    }


@router.post("/logout")
def admin_logout(
    request: Request,
    response: Response,
    access: AdminAccessContext = Depends(verify_admin_session),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
):
    try:
        admin_auth_service.validate_csrf(
            session_token=access.session_token,
            csrf_cookie=request.cookies.get(admin_auth_service.CSRF_COOKIE_NAME, ""),
            csrf_header=x_csrf_token or "",
        )
        admin_auth_service.logout(
            session_token=access.session_token,
            client_ip=client_ip_for_request(request),
            user_agent=user_agent_for_request(request),
        )
    except AdminAuthError as exc:
        _raise_admin_http(exc)
    clear_admin_auth_cookies(response, request)
    return {"ok": True}
