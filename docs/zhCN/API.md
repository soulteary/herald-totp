# herald-totp API 文档

herald-totp 是 TOTP 双因素认证服务：**绑定（enroll）**、**验证（verify）**、以及可选的**恢复码（backup codes）**。不实现“发送”通道；由 Stargate（或登录服务）调用，提供按用户的 TOTP。

## Base URL

```
http://localhost:8084
```

## 鉴权

当配置了 `API_KEY` 或 `HMAC_SECRET` / `HERALD_TOTP_HMAC_KEYS` 时，调用方（如代理 Stargate 请求的 Herald）必须鉴权：

- **API Key**：请求头 `X-API-Key` 与配置一致。
- **HMAC**：发送请求头 `X-Timestamp`、`X-Service`、`X-Signature`。时间戳使用 Unix 秒，body 是请求体的原始字节序列（无请求体时为空），签名是 `HMAC-SHA256(secret, timestamp + ":" + service + ":" + body)` 的小写十六进制编码。当 `HERALD_TOTP_HMAC_KEYS` 包含多个密钥时必须发送 `X-Key-Id`；仅配置一个映射密钥时可省略。

若均未配置，则不鉴权（仅开发环境）。

## Go 客户端

受支持的 Go 客户端位于
`github.com/soulteary/herald-totp/pkg/heraldtotp`：

```go
opts := heraldtotp.DefaultOptions().
	WithBaseURL("http://herald-totp:8084").
	WithAPIKey(os.Getenv("HERALD_TOTP_API_KEY"))

client, err := heraldtotp.NewClient(opts)
if err != nil {
	return err
}

result, err := client.Verify(ctx, &heraldtotp.VerifyRequest{
	Subject:     "user:12345",
	Code:        code,
	ChallengeID: challengeID,
})
```

使用映射 HMAC 密钥时，调用 `WithHMACSecret` 和 `WithHMACKeyID`。默认调用方
服务名为 `stargate`；如需在签名中使用其他调用方身份，可设置
`Options.Service`。

## 接口

### 健康检查

**GET /healthz**

返回服务与 Redis 健康状态（通过 health-kit）。

---

### 指标

**GET /metrics**

返回 Prometheus/OpenMetrics 指标（verify_total、enroll_start_total、enroll_confirm_total）。此接口不需要鉴权。

---

### 开始绑定

**POST /v1/enroll/start**

生成 TOTP secret，返回 `enroll_id` 与 `otpauth_uri`，供前端展示二维码。

**请求体：**

| 字段   | 类型   | 必填 | 说明                                      |
|--------|--------|------|-------------------------------------------|
| subject| string | 是  | 用户标识（如 `user:12345`）。             |
| label  | string | 否  | 在 Authenticator 中显示的账号名（默认 subject）。 |

**响应（200）：**
```json
{
  "enroll_id": "e_01H...",
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_uri": "otpauth://totp/Issuer:label?secret=...&issuer=Issuer&period=30&digits=6"
}
```
当 `EXPOSE_SECRET_IN_ENROLL=false` 时，不返回 `secret_base32`（仅返回用于二维码的 `otpauth_uri`）。

再次发起绑定不会覆盖已有凭证。如需有意重新绑定，应先调用
`POST /v1/revoke`。

**错误：** `400 invalid_request`、`409 already_enrolled`、`409 enrollment_in_progress`、`429 rate_limited`、`500 config_error` 或 `500 internal_error`。

---

### 确认绑定

**POST /v1/enroll/confirm**

用户扫码后输入一次 TOTP 码确认。成功后将凭证落库并可选返回恢复码。

凭证、恢复码哈希和临时绑定记录通过同一个 Redis 事务提交。因此每个 `enroll_id`
只能确认一次，并且仅在恢复码哈希已成功持久化后才会向调用方返回恢复码。
确认绑定使用的 TOTP 计数器会被记录为已消费；使用验证器调用 `/v1/verify`
前应等待进入下一个 TOTP 周期。

**请求体：**

| 字段      | 类型   | 必填 | 说明            |
|-----------|--------|------|-----------------|
| enroll_id| string | 是  | 来自 enroll/start。 |
| code     | string | 是  | 6 位 TOTP 码。  |

**响应（200）：**
```json
{
  "subject": "user:12345",
  "totp_enabled": true,
  "backup_codes": ["ABCD-EFGH-JKLM-NPQR", "WXYZ-2345-6789-ABCD", ...]
}
```

**错误：** `400 expired`、`400 invalid`、`409 already_enrolled` 或 `500 internal_error`。

---

### 验证 TOTP

**POST /v1/verify**

登录时验证 TOTP 码或恢复码。

**请求体：**

| 字段         | 类型   | 必填 | 说明                                |
|--------------|--------|------|-------------------------------------|
| subject      | string | 是  | 用户标识。                          |
| code         | string | 是  | 6 位 TOTP 或恢复码（如 ABCD-EFGH-JKLM-NPQR）。 |
| challenge_id | string | 否  | 可选；用于防重放/审计（一次性）。   |

服务会记录 `TOTP_SKEW` 容差窗口内实际匹配的 TOTP 时间步，并在 Redis 中原子认领。
因此，即使验证码来自相邻时间步，也不能在服务进入该时间步后再次使用。恢复码和非空
`challenge_id` 同样采用原子化的一次性消费。

**响应（200）：**
```json
{
  "ok": true,
  "subject": "user:12345",
  "amr": ["totp"],
  "issued_at": 1706789012
}
```
使用恢复码验证时，`amr` 为 `["totp", "backup_code"]`。

**错误响应：**
```json
{
  "ok": false,
  "reason": "invalid"
}
```

| 状态码 | Reason | 含义 |
|--------|--------|------|
| `400` | `invalid_request` | 缺少必填字段或 JSON 请求体无效。 |
| `400` | `invalid` | subject 没有已启用的 TOTP 凭证。 |
| `401` | `invalid` | 提交的 TOTP 或恢复码无效。 |
| `400` | `replay` | TOTP 计数器或 `challenge_id` 已被消费。 |
| `429` | `rate_limited` | subject 或来源 IP 超过配置的限流值。 |
| `500` | `config_error` | 加密配置无效；启动校验通常会阻止进入此状态。 |
| `500` | `internal_error` | Redis、解密或其他内部操作失败。 |

---

### 解除 TOTP 绑定

**POST /v1/revoke**

移除该用户的 TOTP 凭证与恢复码（解绑）。

凭证和恢复码通过一条 Redis 原子命令删除。存储失败时返回 `500 internal_error`，
不会错误报告解绑成功。

**请求体：**

| 字段   | 类型   | 必填 | 说明        |
|--------|--------|------|-------------|
| subject| string | 是  | 用户标识。  |

**响应（200）：**
```json
{
  "ok": true,
  "subject": "user:12345"
}
```

**错误：** `400 invalid_request`、`429 rate_limited` 或 `500 internal_error`。

---

### 状态查询

**GET /v1/status?subject=user:12345**

查询该用户是否已开启 TOTP。

**响应（200）：**
```json
{
  "subject": "user:12345",
  "totp_enabled": true
}
```

**错误：** `400` invalid_request（缺少 subject），`500` internal_error。
