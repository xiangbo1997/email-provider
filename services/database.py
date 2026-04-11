from __future__ import annotations

import os
from typing import Optional

from sqlmodel import create_engine


_DEFAULT_DATABASE_URL = "sqlite:///mailbox_service.db"
_mailbox_service_engine = None


def current_database_url() -> str:
    return os.getenv("MAILBOX_SERVICE_DATABASE_URL", _DEFAULT_DATABASE_URL)


def create_mailbox_service_engine(database_url: Optional[str] = None):
    url = str(database_url or current_database_url()).strip() or _DEFAULT_DATABASE_URL
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


def get_mailbox_service_engine():
    global _mailbox_service_engine
    if _mailbox_service_engine is None:
        _mailbox_service_engine = create_mailbox_service_engine()
    return _mailbox_service_engine


def reset_mailbox_service_engine(database_url: Optional[str] = None):
    global _mailbox_service_engine
    if database_url is not None:
        os.environ["MAILBOX_SERVICE_DATABASE_URL"] = str(database_url)
    if _mailbox_service_engine is not None:
        try:
            _mailbox_service_engine.dispose()
        except Exception:
            pass
    _mailbox_service_engine = create_mailbox_service_engine(database_url)
    return _mailbox_service_engine
