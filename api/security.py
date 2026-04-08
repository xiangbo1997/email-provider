from __future__ import annotations

import os
import secrets

from fastapi import Header, HTTPException, status


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _auth_disabled() -> bool:
    return _is_truthy(os.getenv("EMAIL_PROVIDER_AUTH_DISABLED"))


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


def verify_api_key(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    if _auth_disabled():
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

    candidate = x_api_key or _extract_bearer_token(authorization)
    if candidate and secrets.compare_digest(candidate, expected):
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "UNAUTHORIZED",
            "message": "missing or invalid API key",
        },
        headers={"WWW-Authenticate": "Bearer"},
    )
