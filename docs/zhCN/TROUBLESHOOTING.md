# herald-totp 故障排查指南

本文帮助诊断和解决 herald-totp 的常见问题。

## 目录

- [服务因配置无效无法启动](#服务因配置无效无法启动)
- [401 Unauthorized](#401-unauthorized)
- [绑定返回 409 Conflict](#绑定返回-409-conflict)
- [验证返回 invalid / replay / rate_limited](#验证返回-invalid--replay--rate_limited)
- [绑定确认返回 expired 或 invalid](#绑定确认返回-expired-或-invalid)
- [解除绑定返回 400 或 429](#解除绑定返回-400-或-429)
- [绑定响应无 secret_base32](#绑定响应无-secret_base32)
- [Redis 连接错误](#redis-连接错误)
- [Stargate 无法访问 herald-totp](#stargate-无法访问-herald-totp)

## 服务因配置无效无法启动

### 现象

- 进程在开始监听前退出，并在日志中输出 `invalid configuration` 及一个或多个无效环境变量。

### 原因

启动时 herald-totp 会集中校验加密密钥、Redis、TOTP、TLS、绑定 TTL 和限流配置。无效配置会直接阻止启动，避免健康检查通过但核心接口不可用。

### 处理

1. 将 `HERALD_TOTP_ENCRYPTION_KEY` 设置为正好 32 字节，可使用 `openssl rand -base64 24` 生成 32 字符的值。重启进程或容器。
2. 确认运行时能读到该变量（环境变量名无拼写错误，Docker/K8s 传参正确）。
3. 查看完整的启动错误；多个无效配置会一次性汇总输出。

---

## 401 Unauthorized

### 现象

- `POST /v1/enroll/start`、`POST /v1/enroll/confirm`、`POST /v1/verify`、`POST /v1/revoke` 或 `GET /v1/status` 返回 HTTP 401，`reason: "unauthorized"` 或 invalid/missing API key / HMAC 错误。

### 原因

herald-totp 已配置 `API_KEY`（或 HMAC），但请求未携带对应头或携带的值与配置不一致。

### 处理

1. **若使用 API Key**  
   - 在 herald-totp 设置 `API_KEY`。  
   - 在 Stargate 设置 `HERALD_TOTP_API_KEY` 为相同值，Stargate 会通过 `X-API-Key` 发送。  
   - 确认中间代理/网关未丢弃 `X-API-Key` 头。

2. **若使用 HMAC**  
   - 在 herald-totp 设置 `HMAC_SECRET` 或 `HERALD_TOTP_HMAC_KEYS`。  
   - 在 Stargate 配置相同密钥（或密钥映射），并确保请求签名使用 `X-Timestamp`、`X-Service`、`X-Signature`。  
   - 检查 Stargate 与 herald-totp 的时钟偏差在可接受范围内（如 60 秒）。

3. **若开发环境不需要鉴权**  
   - 在 herald-totp 不设置 `API_KEY` 与 HMAC（Stargate 侧也不配置 herald-totp 鉴权）。仅限非生产环境。

---

## 绑定返回 409 Conflict

### 现象

- `POST /v1/enroll/start` 返回 `409 already_enrolled` 或
  `409 enrollment_in_progress`。
- `POST /v1/enroll/confirm` 返回 `409 already_enrolled`。

### 原因与处理

- **already_enrolled**：subject 已有 TOTP 凭证，重新绑定不会覆盖它。如确定
  需要替换，应先调用 `POST /v1/revoke`，再发起新绑定。
- **enrollment_in_progress**：subject 已有尚未过期的绑定流程。继续原流程，
  或等待 `ENROLL_TTL` 过期后再重新开始。

---

## 验证返回 invalid / replay / rate_limited

### 现象

- `POST /v1/verify` 返回非 2xx 状态且 `ok: false`。常见映射为
  `400/401 invalid`、`400 replay` 和 `429 rate_limited`。

### 原因与处理

- **invalid**：TOTP 码或恢复码错误，或该 subject 未绑定 TOTP。确认用户输入的是当前验证器中的 6 位码或未使用过的恢复码；确认 subject（如 `user:12345`）与绑定用户一致。
- **replay**：同一 challenge_id（或同一码在时间窗内）已被使用。每次登录使用新的 challenge_id 或不传；成功验证后不要复用 challenge_id。
- **rate_limited**：触发按 subject 或按 IP 的限流。等待限流窗口重置，或根据环境调整 `RATE_LIMIT_PER_SUBJECT` / `RATE_LIMIT_PER_IP`。

enroll/confirm 接受的验证码也会被记录为已消费。使用该验证器进行 verify 前，
需要等待进入下一个 TOTP 周期。

---

## 绑定确认返回 expired 或 invalid

### 现象

- `POST /v1/enroll/confirm` 返回 400，`reason: "expired"` 或 `"invalid"`。

### 原因与处理

- **expired**：来自 `POST /v1/enroll/start` 的 enroll_id 已过期、已被确认或因其他原因不再可用（默认 TTL 10 分钟）。需重新发起绑定：再次调用 enroll/start，让用户扫描新二维码，再向 enroll/confirm 提交新码。
- **invalid**：提交的 6 位 TOTP 与当前临时密钥不匹配。确认用户验证器时间已同步并输入当前码；确认 TOTP 周期（默认 30 秒）与 skew 一致。

---

## 解除绑定返回 400 或 429

### 现象

- `POST /v1/revoke` 返回 400（如 subject 必填）或 429（rate_limited）。

### 原因与处理

- **400 invalid_request**：请求体必须包含 `subject`（用户标识）。发送 `{"subject": "user:12345"}`。
- **429 rate_limited**：触发按 subject 或按 IP 的限流。等待窗口重置或调整 `RATE_LIMIT_PER_SUBJECT` / `RATE_LIMIT_PER_IP`。

---

## 绑定响应无 secret_base32

### 现象

- `POST /v1/enroll/start` 返回 200 但响应中没有 `secret_base32`，仅有 `enroll_id` 和 `otpauth_uri`。

### 原因

`EXPOSE_SECRET_IN_ENROLL` 被设为 `false`（或 `0` / `no`）。生产环境常用此配置避免暴露明文密钥，仅提供 `otpauth_uri` 用于生成二维码。

### 处理

- 若需要明文密钥（如手动输入），设置 `EXPOSE_SECRET_IN_ENROLL=true`（默认）。仅在可信或开发环境使用。
- 若希望隐藏密钥，保持 `false`，仅使用 `otpauth_uri` 生成二维码。

---

## Redis 连接错误

### 现象

- 启动失败或请求失败并报 Redis 连接错误；健康检查返回不健康。

### 处理

1. 确认 `REDIS_ADDR`、`REDIS_PASSWORD`、`REDIS_DB` 正确，且 herald-totp 所在网络能访问 Redis（如同一 Docker 网络或正确主机/端口）。
2. 若 Redis 启用了认证，设置 `REDIS_PASSWORD`。
3. 使用 Redis TLS 时，设置 `REDIS_TLS_ENABLED=true`，将
   `REDIS_TLS_SERVER_NAME` 配置为证书名称；私有 CA 使用
   `REDIS_TLS_CA_FILE`。除本地诊断外保持
   `REDIS_TLS_INSECURE_SKIP_VERIFY=false`。
4. 确认 CA 文件可读取且至少包含一张 PEM 证书。
5. 查看 Redis 服务端日志与资源限制（内存、连接数）。

---

## Stargate 无法访问 herald-totp

### 现象

- Stargate 登录或 TOTP 绑定流程在调用 herald-totp 时出现连接被拒、超时或 5xx。

### 处理

1. 确认 Stargate 的 `HERALD_TOTP_BASE_URL` 指向正确的 herald-totp 地址（如 Docker Compose 中 `http://herald-totp:8084`）。
2. 确认 herald-totp 已启动并在预期端口监听（默认 8084）。检查 `PORT` 环境变量与容器端口映射。
3. 若 Stargate 与 herald-totp 不在同一网络，确保 DNS 或服务发现能解析主机名，且防火墙/安全组放行对应端口。
4. 若使用 HTTPS，确保证书有效且 Stargate 信任（或仅在开发环境使用 insecure_skip_verify）。
