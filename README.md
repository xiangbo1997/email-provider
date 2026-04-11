# email-provider

可复用的邮箱接收服务：统一收口“分配邮箱 / 轮询验证码 / 完成回收”。

## 核心能力

- 统一 provider 适配层（AppleMail / LuckMail / QQEmail 等）
- `/api/mailbox-service/*` 固定接口（推荐给业务系统调用）
- 管理后台 `/admin`（登录后管理 provider 配置与最近会话）
- provider 配置持久化与校验
- 会话租约模型（`session_id + lease_token`）

## 快速启动

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8000
```

容器部署：

```bash
docker compose up -d --build
```

## 鉴权模型

### 1) 邮箱服务 API（保持不变）

`/api/mailbox-service/*` 必须带 API Key：

- `Authorization: Bearer <EMAIL_PROVIDER_API_KEY>`
- 或 `X-API-Key: <EMAIL_PROVIDER_API_KEY>`

### 2) 管理 API 与后台

- 浏览器：`/admin` 使用登录态（Session Cookie + CSRF）
- 脚本：`/api/admin/*` 仍支持 API Key fallback
- 写操作（POST/PUT/DELETE）在 Session 模式下必须 `X-CSRF-Token`

管理登录接口：

- `POST /api/admin/auth/login`
- `GET /api/admin/auth/me`
- `POST /api/admin/auth/logout`

页面路由：

- `GET /admin`（未登录会跳转 `/admin/login`）
- `GET /admin/login`

## 安全与敏感数据

- `lease_token` 仅创建时返回明文，数据库存哈希（兼容历史明文记录读取）
- provider 配置和会话中的敏感字段（`proxy` / `extra` / `provider_meta` 等）支持应用层加密存储
- 管理接口默认附加安全响应头（CSP、X-Frame-Options、no-store 等）
- 错误与事件日志会自动脱敏

> `EMAIL_PROVIDER_DATA_ENCRYPTION_KEY` 现在应视为必配。未配置时，新的敏感数据写入会直接报错；历史明文记录仍可读取。

## 关键环境变量

见 `.env.example`，最少需要：

- `EMAIL_PROVIDER_API_KEY`
- `EMAIL_PROVIDER_ADMIN_USERNAME`
- `EMAIL_PROVIDER_ADMIN_PASSWORD_HASH`
- `EMAIL_PROVIDER_DATA_ENCRYPTION_KEY`
- `MAILBOX_SERVICE_DATABASE_URL`

生成管理员密码哈希：

```bash
python scripts/generate_admin_password_hash.py --password 'your-password'
```

生成数据加密 key：

```bash
python scripts/generate_admin_password_hash.py --generate-data-key
```

## 固定 API 路径

- `GET /api/mailbox-service/health`
- `GET /api/mailbox-service/providers`
- `POST /api/mailbox-service/providers/{provider}/validate-config`
- `POST /api/mailbox-service/sessions`
- `GET /api/mailbox-service/sessions/{session_id}`
- `POST /api/mailbox-service/sessions/{session_id}/poll-code`
- `POST /api/mailbox-service/sessions/{session_id}/complete`
- `GET /api/admin/provider-catalog`
- `GET /api/admin/provider-configs`
- `POST /api/admin/provider-configs`
- `GET /api/admin/provider-configs/{id}`
- `PUT /api/admin/provider-configs/{id}`
- `DELETE /api/admin/provider-configs/{id}`
- `POST /api/admin/provider-configs/{id}/validate`
- `GET /api/admin/recent-sessions`

## 最小回归测试

```bash
python -m unittest \
  tests.test_mailbox_service \
  tests.test_admin_auth_api \
  tests.test_admin_api \
  tests.test_api_security \
  tests.test_applemail_mailbox \
  tests.test_applemail_diagnostics
```
