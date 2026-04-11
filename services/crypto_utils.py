from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_ENCRYPTION_ENV = "EMAIL_PROVIDER_DATA_ENCRYPTION_KEY"
_PREVIOUS_ENCRYPTION_ENV = "EMAIL_PROVIDER_DATA_ENCRYPTION_KEY_PREVIOUS"
_ENVELOPE_VERSION = 1


class CryptoConfigError(RuntimeError):
    pass


_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|auth|refresh[_-]?token|client[_-]?secret|bearer)"
)
_PROXY_CREDENTIAL_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/@\s]+)(?::([^@/\s]+))?@", re.IGNORECASE)
_INLINE_SECRET_RE = re.compile(
    r'(?i)("?(?:password|passwd|pwd|token|secret|api[_-]?key|refresh[_-]?token|client[_-]?secret|bearer|authorization|applemail_accounts)"?\s*[:=]\s*")([^"]+)(")'
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)([^\s,;]+)")


def _b64decode_key(value: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        raise CryptoConfigError(f"{_ENCRYPTION_ENV} is not configured")
    padding = "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(text + padding)
    except Exception as exc:
        raise CryptoConfigError(f"{_ENCRYPTION_ENV} is invalid base64") from exc
    if len(raw) != 32:
        raise CryptoConfigError(f"{_ENCRYPTION_ENV} must decode to 32 bytes")
    return raw


def _load_key_from_env(name: str) -> bytes | None:
    value = os.getenv(name)
    if not value:
        return None
    return _b64decode_key(value)


def _primary_key() -> bytes:
    key = _load_key_from_env(_ENCRYPTION_ENV)
    if key is None:
        raise CryptoConfigError(f"{_ENCRYPTION_ENV} is not configured")
    return key


def _all_candidate_keys() -> list[bytes]:
    keys: list[bytes] = []
    primary = _load_key_from_env(_ENCRYPTION_ENV)
    previous = _load_key_from_env(_PREVIOUS_ENCRYPTION_ENV)
    if primary is not None:
        keys.append(primary)
    if previous is not None and previous not in keys:
        keys.append(previous)
    return keys


def hash_token(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def generate_random_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _envelope_to_json(nonce: bytes, ciphertext: bytes) -> str:
    return json.dumps(
        {
            "v": _ENVELOPE_VERSION,
            "alg": "AES-GCM",
            "kid": "primary",
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _parse_envelope(value: str) -> dict[str, Any] | None:
    text = str(value or "").strip()
    if not text or not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("v") != _ENVELOPE_VERSION:
        return None
    if payload.get("alg") != "AES-GCM":
        return None
    if not payload.get("nonce") or not payload.get("ciphertext"):
        return None
    return payload


def encrypt_string(value: str | None) -> str:
    text = str(value or "")
    if text == "":
        return ""
    aesgcm = AESGCM(_primary_key())
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
    return _envelope_to_json(nonce, ciphertext)


def decrypt_string(value: str | None, default: str = "") -> str:
    text = str(value or "")
    if not text:
        return default
    payload = _parse_envelope(text)
    if payload is None:
        return text
    nonce = base64.urlsafe_b64decode(str(payload["nonce"]).encode("ascii"))
    ciphertext = base64.urlsafe_b64decode(str(payload["ciphertext"]).encode("ascii"))
    errors: list[Exception] = []
    for key in _all_candidate_keys():
        try:
            aesgcm = AESGCM(key)
            plain = aesgcm.decrypt(nonce, ciphertext, None)
            return plain.decode("utf-8")
        except Exception as exc:
            errors.append(exc)
    if not errors:
        raise CryptoConfigError(f"{_ENCRYPTION_ENV} is not configured")
    raise CryptoConfigError("encrypted payload could not be decrypted with configured keys")


def encrypt_json(value: Any) -> str:
    return encrypt_string(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def decrypt_json(value: str | None, default: Any) -> Any:
    text = str(value or "")
    if not text:
        return default
    decrypted = decrypt_string(text, default="")
    try:
        loaded = json.loads(decrypted)
    except Exception:
        if _parse_envelope(text) is not None:
            return default
        try:
            loaded = json.loads(text)
        except Exception:
            return default
    return loaded if loaded is not None else default


def redact_sensitive_text(value: str | None, limit: int = 300) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = _PROXY_CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}***@", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)}***", text)
    text = _INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}***{m.group(3)}", text)
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _looks_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(str(key or "")))


def redact_structure(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if _looks_secret_key(key):
                cleaned[str(key)] = "***"
            else:
                cleaned[str(key)] = redact_structure(item)
        return cleaned
    if isinstance(value, list):
        return [redact_structure(item) for item in value]
    if isinstance(value, tuple):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def mask_proxy(proxy: str | None) -> str:
    text = str(proxy or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except Exception:
        return "configured"
    if not parts.scheme:
        return "configured"
    host = parts.hostname or "configured"
    port = f":{parts.port}" if parts.port else ""
    netloc = host + port
    if parts.username or parts.password:
        netloc = f"***@{netloc}"
    return urlunsplit((parts.scheme, netloc, "", "", ""))
