from __future__ import annotations

import os
import tempfile
from typing import Iterable

TEST_API_KEY = "secret-token"
TEST_ADMIN_USERNAME = "admin"
TEST_ADMIN_PASSWORD = "Passw0rd!123"
TEST_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def prepare_test_environment(db_name: str) -> str:
    db_path = os.path.join(tempfile.gettempdir(), db_name)
    os.environ["MAILBOX_SERVICE_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["EMAIL_PROVIDER_API_KEY"] = TEST_API_KEY
    os.environ["EMAIL_PROVIDER_DATA_ENCRYPTION_KEY"] = TEST_ENCRYPTION_KEY
    os.environ["EMAIL_PROVIDER_ADMIN_USERNAME"] = TEST_ADMIN_USERNAME
    os.environ.setdefault("EMAIL_PROVIDER_ADMIN_SESSION_TTL_SECONDS", "28800")
    return db_path


def bootstrap_database(db_name: str) -> str:
    db_path = prepare_test_environment(db_name)

    from services.admin_auth_service import admin_auth_service, init_admin_auth_db
    from services.database import reset_mailbox_service_engine
    from services.mailbox_service import init_mailbox_service_db

    os.environ["EMAIL_PROVIDER_ADMIN_PASSWORD_HASH"] = admin_auth_service.create_password_hash(TEST_ADMIN_PASSWORD)
    reset_mailbox_service_engine(f"sqlite:///{db_path}")
    init_mailbox_service_db()
    init_admin_auth_db()
    return db_path


def clean_database(models: Iterable[type]) -> None:
    from sqlmodel import Session, delete

    from services.database import get_mailbox_service_engine

    with Session(get_mailbox_service_engine()) as session:
        for model in models:
            session.exec(delete(model))
        session.commit()
