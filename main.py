import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from api.admin import router as admin_router
from api.admin_auth import router as admin_auth_router
from api.mailbox_service import router as mailbox_service_router
from api.security import apply_response_security_headers, get_optional_admin_session
from services.admin_auth_service import init_admin_auth_db
from services.mailbox_service import (
    MailboxServiceError,
    ProviderConfigIncompleteError,
    ProviderUpstreamError,
    init_mailbox_service_db,
)


logger = logging.getLogger(__name__)


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


# ---------------------------------------------------------------------------
# 全局业务异常映射。注册 ProviderConfigIncompleteError / ProviderUpstreamError /
# MailboxServiceError 三类业务异常 → 结构化 4xx；同时把所有漏到这里的裸
# RuntimeError 兜成结构化 500，避免再返回纯文本 ``Internal Server Error``。
# 端点函数不再写重复 try/except — 业务异常自然向上抛由 handler 渲染。
# ---------------------------------------------------------------------------


def _error_body(code: str, message: str, **extra: object) -> dict[str, object]:
    detail: dict[str, object] = {"code": code, "message": message}
    detail.update(extra)
    return {"detail": detail}


@app.exception_handler(ProviderConfigIncompleteError)
async def _handle_provider_config_incomplete(
    request: Request, exc: ProviderConfigIncompleteError
):
    return JSONResponse(
        status_code=422,
        content=_error_body(
            exc.code,
            exc.message,
            missing_fields=list(exc.missing_fields),
        ),
    )


@app.exception_handler(ProviderUpstreamError)
async def _handle_provider_upstream(request: Request, exc: ProviderUpstreamError):
    return JSONResponse(
        status_code=424,
        content=_error_body(
            exc.code,
            exc.message,
            upstream_status=int(exc.upstream_status or 0),
        ),
    )


@app.exception_handler(MailboxServiceError)
async def _handle_mailbox_error(request: Request, exc: MailboxServiceError):
    code = str(getattr(exc, "code", "") or "MAILBOX_ERROR")
    message = str(getattr(exc, "message", "") or "")
    status_code = 400
    if code.endswith("_NOT_FOUND"):
        status_code = 404
    elif code.endswith("_EXISTS"):
        status_code = 409
    elif code in {"INVALID_LEASE"}:
        status_code = 401
    elif code in {"LEASE_EXPIRED"}:
        status_code = 410
    elif code in {"ENCRYPTION_NOT_CONFIGURED"}:
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content=_error_body(code, message),
    )


@app.exception_handler(RuntimeError)
async def _handle_runtime_error(request: Request, exc: RuntimeError):
    # 业务异常已通过更具体的 handler 处理。这里兜底所有未分类 RuntimeError，
    # 仍返回 500 但带结构化 body（之前裸 ``Internal Server Error`` 让客户端
    # 完全无法判断是配置问题还是真实故障）。
    logger.error(
        "未分类 RuntimeError 触发 500: path=%s message=%s",
        getattr(request, "url", ""),
        exc,
    )
    return JSONResponse(
        status_code=500,
        content=_error_body("INTERNAL_ERROR", str(exc)[:300]),
    )


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
