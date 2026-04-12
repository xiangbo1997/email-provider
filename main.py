import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from api.admin import router as admin_router
from api.admin_auth import router as admin_auth_router
from api.mailbox_service import router as mailbox_service_router
from api.security import apply_response_security_headers, get_optional_admin_session
from services.admin_auth_service import init_admin_auth_db
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
    init_admin_auth_db()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    return apply_response_security_headers(request, response)


app.include_router(mailbox_service_router, prefix="/api")
app.include_router(admin_auth_router, prefix="/api")
app.include_router(admin_router, prefix="/api")
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/")
def root():
    return {"name": "email-provider", "ok": True}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/admin", response_class=HTMLResponse)
def admin_console(request: Request):
    if not get_optional_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=303)
    return HTMLResponse((_admin_dir / "index.html").read_text(encoding="utf-8"))


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    if get_optional_admin_session(request):
        return RedirectResponse(url="/admin", status_code=303)
    return HTMLResponse((_admin_dir / "login.html").read_text(encoding="utf-8"))
