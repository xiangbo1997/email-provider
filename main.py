import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from api.admin import router as admin_router
from api.mailbox_service import router as mailbox_service_router
from services.mailbox_service import init_mailbox_service_db


def _is_truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


_docs_enabled = _is_truthy(os.getenv("EMAIL_PROVIDER_EXPOSE_DOCS"))
_base_dir = Path(__file__).resolve().parent
_static_dir = _base_dir / "static"
_admin_dir = _static_dir / "admin"

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
app.include_router(admin_router, prefix="/api")
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/")
def root():
    return {"name": "email-provider", "ok": True}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/admin", response_class=HTMLResponse)
def admin_console():
    return (_admin_dir / "index.html").read_text(encoding="utf-8")
