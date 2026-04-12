from __future__ import annotations

import os

from sqlmodel import Session, delete

from services.admin_auth_service import (
    AdminAuthEventModel,
    AdminLoginAttemptModel,
    AdminWebSessionModel,
    admin_auth_service,
    init_admin_auth_db,
)
from services.crypto_utils import generate_random_key
from services.database import get_mailbox_service_engine, reset_mailbox_service_engine
from services.mailbox_service import (
    MailboxProviderConfigModel,
    MailboxSessionEventModel,
    MailboxSessionModel,
    init_mailbox_service_db,
)


DEFAULT_API_KEY = "secret-token"
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin-password"


def configure_test_env(db_path: str) -> None:
    os.environ["MAILBOX_SERVICE_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["EMAIL_PROVIDER_API_KEY"] = DEFAULT_API_KEY
    os.environ["EMAIL_PROVIDER_DATA_ENCRYPTION_KEY"] = generate_random_key()
    os.environ.pop("EMAIL_PROVIDER_DATA_ENCRYPTION_KEY_PREVIOUS", None)
    os.environ["EMAIL_PROVIDER_ADMIN_USERNAME"] = DEFAULT_ADMIN_USERNAME
    os.environ["EMAIL_PROVIDER_ADMIN_PASSWORD_HASH"] = admin_auth_service.create_password_hash(DEFAULT_ADMIN_PASSWORD)
    os.environ["EMAIL_PROVIDER_ADMIN_SESSION_TTL_SECONDS"] = "3600"
    os.environ.pop("EMAIL_PROVIDER_AUTH_DISABLED", None)
    reset_mailbox_service_engine(os.environ["MAILBOX_SERVICE_DATABASE_URL"])
    init_mailbox_service_db()
    init_admin_auth_db()


def engine():
    return get_mailbox_service_engine()


def clean_all_tables() -> None:
    with Session(engine()) as session:
        session.exec(delete(AdminAuthEventModel))
        session.exec(delete(AdminWebSessionModel))
        session.exec(delete(AdminLoginAttemptModel))
        session.exec(delete(MailboxSessionEventModel))
        session.exec(delete(MailboxSessionModel))
        session.exec(delete(MailboxProviderConfigModel))
        session.commit()
