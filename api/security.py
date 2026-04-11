from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Literal

from fastapi import Depends, Header, HTTPException, Request, Response, status

from services.admin_auth_service import AdminAuthError, AdminSessionIdentity, admin_auth_service


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _api_key_auth_disabled() -> bool:
    return _is_truthy(os.getenv("EMAIL_PROVIDER_AUTH_DISABLED"))


def _trust_proxy_headers() -> bool:
    return _is_truthy(os.getenv("EMAIL_PROVIDER_TRUST_PROXY_HEADERS"))


def _expected_api_key() -> str:
    return str(
        os.getenv("EMAIL_PROVIDER_API_KEY")
        or os.getenv("MAILBOX_SERVICE_API_KEY")
        or ""
    ).strip()


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        return ""
    prefix = "bearer "
    text = authorization.strip()
    if text.lower().startswith(prefix):
        return text[len(prefix):].strip()
    return ""


def client_ip_for_request(request: Request) -> str:
    if _trust_proxy_headers():
        forwarded_for = request.headers.get("x-forwarded-for", "")
        if forwarded_for:
            return forwarded_for.split(",", 1)[0].strip()
    return str(getattr(request.client, "host", "") or "")


def request_is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    if _trust_proxy_headers():
        return request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() == "https"
    return False


def user_agent_for_request(request: Request) -> str:
    return request.headers.get("user-agent", "")


def _api_key_candidate(authorization: str | None, x_api_key: str | None) -> str:
    return str(x_api_key or _extract_bearer_token(authorization) or "").strip()


def api_key_is_valid(
    authorization: str | None = None,
    x_api_key: str | None = None,
    *,
    allow_disabled: bool = True,
) -> bool:
    if allow_disabled and _api_key_auth_disabled():
        return True
    expected = _expected_api_key()
    if not expected:
        return False
    candidate = _api_key_candidate(authorization, x_api_key)
    return bool(candidate and secrets.compare_digest(candidate, expected))


def verify_api_key(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    if _api_key_auth_disabled():
        return

    expected = _expected_api_key()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_NOT_CONFIGURED",
                "message": "email-provider API key is not configured",
            },
        )

    if api_key_is_valid(authorization, x_api_key):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "UNAUTHORIZED",
            "message": "missing or invalid API key",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


@dataclass
class AdminAccessContext:
    auth_mode: Literal["api_key", "session"]
    username: str
    session_token: str = ""
    session: AdminSessionIdentity | None = None


_ADMIN_CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
)


def apply_response_security_headers(request: Request, response: Response) -> Response:
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=(), payment=()",
    )
    path = request.url.path
    if path.startswith("/admin") or path.startswith("/api/admin"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
        response.headers.setdefault("Content-Security-Policy", _ADMIN_CSP)
    if request_is_secure(request):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _raise_admin_http(exc: AdminAuthError):
    headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == status.HTTP_401_UNAUTHORIZED else None
    raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}, headers=headers)


def get_optional_admin_session(request: Request) -> AdminSessionIdentity | None:
    session_token = request.cookies.get(admin_auth_service.SESSION_COOKIE_NAME, "")
    if not session_token:
        return None
    try:
        return admin_auth_service.authenticate_session(
            session_token=session_token,
            client_ip=client_ip_for_request(request),
            user_agent=user_agent_for_request(request),
        )
    except AdminAuthError:
        return None


def verify_admin_session(request: Request) -> AdminAccessContext:
    session_token = request.cookies.get(admin_auth_service.SESSION_COOKIE_NAME, "")
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "message": "admin login required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        session = admin_auth_service.authenticate_session(
            session_token=session_token,
            client_ip=client_ip_for_request(request),
            user_agent=user_agent_for_request(request),
        )
    except AdminAuthError as exc:
        _raise_admin_http(exc)
    return AdminAccessContext(auth_mode="session", username=session.username, session_token=session_token, session=session)


def verify_admin_access(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> AdminAccessContext:
    if api_key_is_valid(authorization, x_api_key, allow_disabled=False):
        return AdminAccessContext(auth_mode="api_key", username="api-key")
    return verify_admin_session(request)


def verify_admin_write_access(
    request: Request,
    access: AdminAccessContext = Depends(verify_admin_access),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> AdminAccessContext:
    if access.auth_mode == "api_key":
        return access
    csrf_cookie = request.cookies.get(admin_auth_service.CSRF_COOKIE_NAME, "")
    try:
        admin_auth_service.validate_csrf(
            session_token=access.session_token,
            csrf_cookie=csrf_cookie,
            csrf_header=x_csrf_token or "",
        )
    except AdminAuthError as exc:
        _raise_admin_http(exc)
    return access


def admin_cookie_secure_enabled(request: Request) -> bool:
    if _is_truthy(os.getenv("EMAIL_PROVIDER_ADMIN_COOKIE_SECURE")):
        return True
    return request_is_secure(request)


def set_admin_auth_cookies(response: Response, request: Request, *, session_token: str, csrf_token: str, max_age: int) -> None:
    secure = admin_cookie_secure_enabled(request)
    same_site = "lax"
    response.set_cookie(
        admin_auth_service.SESSION_COOKIE_NAME,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=same_site,
        path="/",
    )
    response.set_cookie(
        admin_auth_service.CSRF_COOKIE_NAME,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite=same_site,
        path="/",
    )


def clear_admin_auth_cookies(response: Response, request: Request) -> None:
    secure = admin_cookie_secure_enabled(request)
    same_site = "lax"
    response.delete_cookie(admin_auth_service.SESSION_COOKIE_NAME, path="/", secure=secure, samesite=same_site)
    response.delete_cookie(admin_auth_service.CSRF_COOKIE_NAME, path="/", secure=secure, samesite=same_site)
