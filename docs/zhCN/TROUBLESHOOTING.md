# herald-totp 故障排查指南

本文帮助诊断和解决 herald-totp 的常见问题。

## 目录

- [绑定或验证失败（config_error）](#绑定或验证失败config_error)
- [401 Unauthorized](#401-unauthorized)
- [验证返回 invalid / expired / replay / rate_limited](#验证返回-invalid--expired--replay--rate_limited)
- [绑定确认返回 expired 或 invalid](#绑定确认返回-expired-或-invalid)
- [Redis 连接错误](#redis-连接错误)
- [Stargate 无法访问 herald-totp](#stargate-无法访问-herald-totp)

## 绑定或验证失败（config_error）

### 现象

- `POST /v1/enroll/start`、`POST /v1/enroll/confirm` 或 `POST /v1/verify` 返回 HTTP 500，提示加密密钥未配置或无效。

### 原因

启动时 herald-totp 会检查 `HERALD_TOTP_ENCRYPTION_KEY` 已设置且不少于 32 字节。若未设置或过短，服务会打印警告，enroll/verify 将返回 config_error。

### 处理

1. 将 `HERALD_TOTP_ENCRYPTION_KEY` 设置为 32 字节（如 32 个 ASCII 字符或 64 个十六进制字符解码为 32 字节）。重启进程或容器。
2. 确认运行时能读到该变量（环境变量名无拼写错误，Docker/K8s 传参正确）。
3. 查看启动日志：若密钥缺失或过短，会打印 enroll/verify 将失败类警告。

---

## 401 Unauthorized

### 现象

- `POST /v1/enroll/start`、`POST /v1/enroll/confirm`、`POST /v1/verify` 或 `GET /v1/status` 返回 HTTP 401，`reason: "unauthorized"` 或 invalid/missing API key / HMAC 错误。

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

## 验证返回 invalid / expired / replay / rate_limited

### 现象

- `POST /v1/verify` 返回 200 且 `ok: false`，`reason` 为 `"invalid"`、`"expired"`、`"replay"` 或 `"rate_limited"`。

### 原因与处理

- **invalid**：TOTP 码或恢复码错误，或该 subject 未绑定 TOTP。确认用户输入的是当前验证器中的 6 位码或未使用过的恢复码；确认 subject（如 `user:12345`）与绑定用户一致。
- **expired**：多用于 enroll（enroll_id 过期）。验证时确保用户 TOTP 仍存在（status 返回 totp_enabled: true）。
- **replay**：同一 challenge_id（或同一码在时间窗内）已被使用。每次登录使用新的 challenge_id 或不传；成功验证后不要复用 challenge_id。
- **rate_limited**：触发按 subject 或按 IP 的限流。等待限流窗口重置，或根据环境调整 `RATE_LIMIT_PER_SUBJECT` / `RATE_LIMIT_PER_IP`。

---

## 绑定确认返回 expired 或 invalid

### 现象

- `POST /v1/enroll/confirm` 返回 400，`reason: "expired"` 或 `"invalid"`。

### 原因与处理

- **expired**：来自 `POST /v1/enroll/start` 的 enroll_id 已过期（默认 TTL 10 分钟）。需重新发起绑定：再次调用 enroll/start，让用户扫描新二维码，再向 enroll/confirm 提交新码。
- **invalid**：提交的 6 位 TOTP 与当前临时密钥不匹配。确认用户验证器时间已同步并输入当前码；确认 TOTP 周期（默认 30 秒）与 skew 一致。

---

## Redis 连接错误

### 现象

- 启动失败或请求失败并报 Redis 连接错误；健康检查返回不健康。

### 处理

1. 确认 `REDIS_ADDR`、`REDIS_PASSWORD`、`REDIS_DB` 正确，且 herald-totp 所在网络能访问 Redis（如同一 Docker 网络或正确主机/端口）。
2. 若 Redis 启用了认证，设置 `REDIS_PASSWORD`。若使用 TLS，确保客户端配置（若驱动支持）正确。
3. 查看 Redis 服务端日志与资源限制（内存、连接数）。确保 herald-totp 连接池大小足够。

---

## Stargate 无法访问 herald-totp

### 现象

- Stargate 登录或 TOTP 绑定流程在调用 herald-totp 时出现连接被拒、超时或 5xx。

### 处理

1. 确认 Stargate 的 `HERALD_TOTP_BASE_URL` 指向正确的 herald-totp 地址（如 Docker Compose 中 `http://herald-totp:8084`）。
2. 确认 herald-totp 已启动并在预期端口监听（默认 8084）。检查 `PORT` 环境变量与容器端口映射。
3. 若 Stargate 与 herald-totp 不在同一网络，确保 DNS 或服务发现能解析主机名，且防火墙/安全组放行对应端口。
4. 若使用 HTTPS，确保证书有效且 Stargate 信任（或仅在开发环境使用 insecure_skip_verify）。
