# email-provider

可复用的邮箱接收服务，抽离自 `any-auto-register`。

当前仓库包含：

- 统一邮箱 provider 适配层
- 会话/租约式邮箱服务核心
- FastAPI 路由
- AppleMail 诊断工具
- 基础回归测试

当前接口：

- `GET /api/mailbox-service/health`
- `GET /api/mailbox-service/providers`
- `POST /api/mailbox-service/providers/{provider}/validate-config`
- `POST /api/mailbox-service/sessions`
- `GET /api/mailbox-service/sessions/{id}`
- `POST /api/mailbox-service/sessions/{id}/poll-code`
- `POST /api/mailbox-service/sessions/{id}/complete`
