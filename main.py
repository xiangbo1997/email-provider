import os

from fastapi import FastAPI

from api.mailbox_service import router as mailbox_service_router
from services.mailbox_service import init_mailbox_service_db


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


_docs_enabled = _is_truthy(os.getenv("EMAIL_PROVIDER_EXPOSE_DOCS"))

app = FastAPI(
    title="email-provider",
    version="0.1.0",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)


@app.on_event("startup")
def on_startup():
    init_mailbox_service_db()


app.include_router(mailbox_service_router, prefix="/api")


@app.get("/")
def root():
    return {"name": "email-provider", "ok": True}


@app.get("/healthz")
def healthz():
    return {"ok": True}
