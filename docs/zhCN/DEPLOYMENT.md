# herald-totp 部署说明

## 要求

- Go 1.25+
- Redis（用于凭证、绑定临时态、恢复码、限流）

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| PORT | :8084 | 监听地址。 |
| LOG_LEVEL | info | 日志级别。 |
| REDIS_ADDR | localhost:6379 | Redis 地址。 |
| REDIS_PASSWORD | | Redis 密码。 |
| REDIS_DB | 0 | Redis 库号。 |
| TOTP_ISSUER | Herald | otpauth URI 中的 Issuer。 |
| TOTP_PERIOD | 30 | TOTP 周期（秒）。 |
| TOTP_DIGITS | 6 | TOTP 位数。 |
| TOTP_SKEW | 1 | 时间步长偏移（步数）。 |
| ENROLL_TTL | 10m | 绑定临时态 TTL。 |
| HERALD_TOTP_ENCRYPTION_KEY | | **必填**，用于 enroll/verify。32 字节 AES-256 密钥（secret 加密）。 |
| API_KEY | | 可选；服务鉴权。 |
| HMAC_SECRET | | 可选；HMAC 鉴权。 |
| HERALD_TOTP_HMAC_KEYS | | 可选；JSON 密钥映射，支持轮换。 |
| SERVICE_NAME | herald-totp | 服务名（如 HMAC 用）。 |
| RATE_LIMIT_PER_SUBJECT | 20 | 每 subject 每小时请求上限。 |
| RATE_LIMIT_PER_IP | 30 | 每 IP 每分钟请求上限。 |

## 运行

```bash
export HERALD_TOTP_ENCRYPTION_KEY="your-32-byte-secret-key-here!!"
go run .
```

或参考 [.env.example](../.env.example)，配合进程管理 / Docker 使用。

## 与 Stargate、Herald 集成

1. **Stargate**：仅设置 `HERALD_TOTP_ENABLED=true`（TOTP 经 Herald 代理）。
2. **Herald**：设置 `HERALD_TOTP_ENABLED=true`、`HERALD_TOTP_BASE_URL=http://herald-totp:8084`，以及 `HERALD_TOTP_API_KEY` 或 `HERALD_TOTP_HMAC_SECRET`。Herald 将 `/v1/totp/*` 代理到 herald-totp。
3. **登录流程**：用户输入 TOTP 码；Stargate 调用 Herald `/v1/totp/verify`；Herald 转发到 herald-totp。
4. **绑定流程**：用户登录后打开 Stargate `/totp/enroll`；Stargate 调用 Herald 的 enroll/start 与 enroll/confirm；Herald 转发到 herald-totp。

## 健康检查

- **GET /healthz**：包含 Redis 检查，可用于就绪/存活探针。

## 监控

- **GET /metrics**：Prometheus 指标（OpenMetrics 格式）。

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| herald_totp_verify_total | Counter | result, reason | TOTP 验证次数（result: success/failure，reason: totp, invalid, replay, rate_limited, backup_code）。 |
| herald_totp_enroll_start_total | Counter | - | enroll/start 调用次数。 |
| herald_totp_enroll_confirm_total | Counter | result | enroll/confirm 按结果统计（success/failure）。 |

## 安全

- `HERALD_TOTP_ENCRYPTION_KEY` 需保密且不少于 32 字节。
- 服务间调用使用 API Key 或 HMAC。
- herald-totp 部署在内网，不要直接暴露公网。
