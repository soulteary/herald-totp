# herald-totp API 文档

herald-totp 是 TOTP 双因素认证服务：**绑定（enroll）**、**验证（verify）**、以及可选的**恢复码（backup codes）**。不实现“发送”通道；由 Stargate（或登录服务）调用，提供按用户的 TOTP。

## Base URL

```
http://localhost:8084
```

## 鉴权

当配置了 `API_KEY` 或 `HMAC_SECRET` / `HERALD_TOTP_HMAC_KEYS` 时，调用方（如 Stargate）必须鉴权：

- **API Key**：请求头 `X-API-Key` 与配置一致。
- **HMAC**：请求头 `X-Timestamp`、`X-Service`、`X-Signature`（可选 `X-Key-Id`）。签名为 `HMAC-SHA256(secret, timestamp + ":" + service + ":" + body)`。

若均未配置，则不鉴权（仅开发环境）。

## 接口

### 健康检查

**GET /healthz**

返回服务与 Redis 健康状态（通过 health-kit）。

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

**错误：** `400` invalid_request，`429` rate_limited，`500` config_error / internal_error。

---

### 确认绑定

**POST /v1/enroll/confirm**

用户扫码后输入一次 TOTP 码确认。成功后将凭证落库并可选返回恢复码。

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
  "backup_codes": ["ABCD-EFGH", "WXYZ-1234", ...]
}
```

**错误：** `400` expired（绑定不存在或过期）、invalid（码错误），`500` internal_error。

---

### 验证 TOTP

**POST /v1/verify**

登录时验证 TOTP 码或恢复码。

**请求体：**

| 字段         | 类型   | 必填 | 说明                                |
|--------------|--------|------|-------------------------------------|
| subject      | string | 是  | 用户标识。                          |
| code         | string | 是  | 6 位 TOTP 或恢复码（如 ABCD-EFGH）。 |
| challenge_id | string | 否  | 可选；用于防重放/审计（一次性）。   |

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

**错误响应（4xx）：**
```json
{
  "ok": false,
  "reason": "invalid" | "expired" | "replay" | "rate_limited"
}
```

---

### 解除 TOTP 绑定

**POST /v1/revoke**

移除该用户的 TOTP 凭证与恢复码（解绑）。

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

**错误：** `400` invalid_request（缺少 subject），`429` rate_limited。

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
