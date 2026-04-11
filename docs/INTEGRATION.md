# Email Provider Integration Guide

## 1. 推荐集成方式

优先把本仓库当做 HTTP 服务接入，不要直接依赖 provider 内部类。

标准 OTP 流程：

1. `POST /api/mailbox-service/sessions`
2. 用返回的 `email` 触发上游发码
3. `POST /api/mailbox-service/sessions/{id}/poll-code`
4. 无论成功失败都 `POST /api/mailbox-service/sessions/{id}/complete`

## 2. 鉴权与会话模型

### 2.1 `/api/mailbox-service/*`

只接受 API Key：

- `Authorization: Bearer <EMAIL_PROVIDER_API_KEY>`
- 或 `X-API-Key: <EMAIL_PROVIDER_API_KEY>`

### 2.2 `/api/admin/*` 与 `/admin`

- 浏览器后台：登录态（Session Cookie）+ CSRF
- 自动化脚本：允许 API Key fallback

新增认证接口：

- `POST /api/admin/auth/login`
- `GET /api/admin/auth/me`
- `POST /api/admin/auth/logout`

页面入口：

- `GET /admin`（未登录 302 到 `/admin/login`）
- `GET /admin/login`

> 注意：`EMAIL_PROVIDER_AUTH_DISABLED=1` 只会影响 mailbox-service 的 API Key 校验，不会绕过 admin 登录。

## 3. 关键 API

### 3.1 mailbox-service

- `GET /api/mailbox-service/health`
- `GET /api/mailbox-service/providers`
- `POST /api/mailbox-service/providers/{provider}/validate-config`
- `POST /api/mailbox-service/sessions`
- `GET /api/mailbox-service/sessions/{session_id}`
- `POST /api/mailbox-service/sessions/{session_id}/poll-code`
- `POST /api/mailbox-service/sessions/{session_id}/complete`

### 3.2 admin

- `GET /api/admin/provider-catalog`
- `GET /api/admin/provider-configs`
- `POST /api/admin/provider-configs`
- `GET /api/admin/provider-configs/{id}`
- `PUT /api/admin/provider-configs/{id}`
- `DELETE /api/admin/provider-configs/{id}`
- `POST /api/admin/provider-configs/{id}/validate`
- `GET /api/admin/recent-sessions`

## 4. provider 配置接口语义

`GET /api/admin/provider-configs` 返回**摘要列表**，默认不回传敏感详情：

- 包含：`id/name/provider/enabled/description/proxy_masked/...`
- 不包含：`extra` 明文、`proxy` 明文

`GET /api/admin/provider-configs/{id}` 返回配置详情（含解密后的 `extra` 和 `proxy`）。

## 5. 会话与租约语义

- `session_id`：服务层会话 ID
- `lease_token`：会话操作凭证

当前实现中：

- 创建会话时只返回一次 `lease_token` 明文
- 数据库只持久化 `lease_token` 哈希（兼容读取历史明文）

## 6. 数据安全

敏感字段支持应用层加密存储（建议生产强制启用）：

- provider config：`proxy`、`extra_json`
- mailbox session：`proxy`、`config_json`、`account_extra_json`、`provider_meta_json`

环境变量：

- `EMAIL_PROVIDER_DATA_ENCRYPTION_KEY`（必配，32 字节 base64url）
- `EMAIL_PROVIDER_DATA_ENCRYPTION_KEY_PREVIOUS`（可选，用于轮换）

未配置 key 时，新的敏感字段写入会失败；历史明文记录仍可兼容读取。

## 7. 部署建议

- 尽量仅监听内网或 `127.0.0.1`
- 通过网关或反代提供 TLS
- 生产启用：
  - `EMAIL_PROVIDER_ADMIN_COOKIE_SECURE=1`
  - `EMAIL_PROVIDER_TRUST_PROXY_HEADERS=1`（仅在可信反代后）
- 定期轮换 API Key、admin 密码哈希和数据加密 key

## 8. 运维辅助脚本

生成管理员密码哈希：

```bash
python scripts/generate_admin_password_hash.py --password 'your-password'
```

生成数据加密 key：

```bash
python scripts/generate_admin_password_hash.py --generate-data-key
```

## 9. 最小验证

```bash
python -m unittest \
  tests.test_mailbox_service \
  tests.test_admin_auth_api \
  tests.test_admin_api \
  tests.test_api_security \
  tests.test_applemail_mailbox \
  tests.test_applemail_diagnostics
```
