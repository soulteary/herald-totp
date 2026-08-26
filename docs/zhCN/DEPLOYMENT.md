# herald-totp 部署说明

## 要求

- Go 1.26+
- Redis（用于凭证、绑定临时态、恢复码、限流）

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| PORT | :8084 | 非空监听端口，可带或不带前导冒号。 |
| LOG_LEVEL | info | 日志级别。 |
| REDIS_ADDR | localhost:6379 | 非空 Redis 地址。 |
| REDIS_PASSWORD | | Redis 密码。 |
| REDIS_DB | 0 | Redis 库号，必须为非负数。 |
| REDIS_TLS_ENABLED | false | 使用 TLS 连接 Redis。 |
| REDIS_TLS_SERVER_NAME | | Redis 证书中预期的服务端名称；要求 `REDIS_TLS_ENABLED=true`。 |
| REDIS_TLS_CA_FILE | | 可选 Redis PEM CA 证书包；要求已启用 TLS。 |
| REDIS_TLS_INSECURE_SKIP_VERIFY | false | 关闭证书校验，仅用于诊断且要求已启用 TLS。 |
| TOTP_ISSUER | Herald | otpauth URI 中的非空 Issuer。 |
| TOTP_PERIOD | 30 | TOTP 周期，范围 `1` 到 `300` 秒。 |
| TOTP_DIGITS | 6 | TOTP 位数，只能为 `6` 或 `8`。 |
| TOTP_SKEW | 1 | 时间步偏移，范围 `0` 到 `10`。 |
| ENROLL_TTL | 10m | 绑定临时态 TTL，必须为正值。 |
| HERALD_TOTP_ENCRYPTION_KEY | | **启动必填**；正好 32 字节，用于 AES-256-GCM。 |
| API_KEY | | 可选；服务鉴权。 |
| HMAC_SECRET | | 可选；HMAC 鉴权。 |
| HERALD_TOTP_HMAC_KEYS | | 可选的非空 JSON 密钥映射；密钥 ID 和密钥均不得为空。 |
| SERVICE_NAME | herald-totp | 健康检查接口报告的服务名称。 |
| EXPOSE_SECRET_IN_ENROLL | true | enroll/start 是否返回 `secret_base32`；生产环境不需要手动录入时建议设为 `false`。 |
| RATE_LIMIT_PER_SUBJECT | 20 | 每 subject 固定一小时窗口的正整数请求上限；窗口从首次请求开始。 |
| RATE_LIMIT_PER_IP | 30 | 每 IP 固定一分钟窗口的正整数请求上限；窗口从首次请求开始。 |

启动时会一次性报告全部配置校验问题，并在监听端口或初始化 Redis 前退出。

## 运行

```bash
export HERALD_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 24)"
go run .
```

使用 Redis TLS 时，启用 `REDIS_TLS_ENABLED`，将 `REDIS_TLS_SERVER_NAME`
设置为证书名称；私有 CA 可通过 `REDIS_TLS_CA_FILE` 提供。部署环境应保持
`REDIS_TLS_INSECURE_SKIP_VERIFY=false`。

也可复制 [`.env.example`](../../.env.example)，替换其中所有密钥占位符后，
配合进程管理器或容器运行时使用。该示例文件不能直接作为生产配置。

## 发布产物

每个版本会发布 Linux、macOS、Windows 二进制文件以及 `checksums.txt`，
并向 GHCR 发布多架构容器镜像：

```bash
docker pull ghcr.io/soulteary/herald-totp:v1.0.0
```

部署时应使用完整版本标签以保证结果可复现。发布流程也会生成不带前导 `v`
的 SemVer 别名。

## 与 Stargate、Herald 集成

1. **Stargate**：仅设置 `HERALD_TOTP_ENABLED=true`（TOTP 经 Herald 代理）。
2. **Herald**：设置 `HERALD_TOTP_ENABLED=true`、`HERALD_TOTP_BASE_URL=http://herald-totp:8084`，以及 `HERALD_TOTP_API_KEY` 或 `HERALD_TOTP_HMAC_SECRET`。Herald 将 `/v1/totp/*` 代理到 herald-totp。
3. **登录流程**：用户输入 TOTP 码；Stargate 调用 Herald `/v1/totp/verify`；Herald 转发到 herald-totp。
4. **绑定流程**：用户登录后打开 Stargate `/totp/enroll`；Stargate 调用 Herald 的 enroll/start 与 enroll/confirm；Herald 转发到 herald-totp。

## 健康检查

- **GET /healthz**：包含 Redis 依赖检查，适合作为就绪探针。不要直接作为
  Kubernetes 存活探针，否则 Redis 故障会导致健康的应用进程被反复重启。
  当前没有单独提供不依赖外部服务的 HTTP 存活接口。

## 监控

- **GET /metrics**：Prometheus 指标（OpenMetrics 格式）。

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| herald_totp_verify_total | Counter | result, reason | TOTP 验证次数（result: success/failure，reason: totp, invalid, replay, rate_limited, backup_code）。 |
| herald_totp_enroll_start_total | Counter | - | enroll/start 调用次数。 |
| herald_totp_enroll_confirm_total | Counter | result | enroll/confirm 按结果统计（success/failure）。 |

## 安全

- `HERALD_TOTP_ENCRYPTION_KEY` 需保密且必须正好为 32 字节。
- 服务间调用使用 API Key 或 HMAC。
- herald-totp 部署在内网，不要直接暴露公网。
- 官方容器以非特权用户和用户组 `10001:10001` 运行。
