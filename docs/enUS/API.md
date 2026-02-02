# herald-totp API Documentation

herald-totp is a TOTP 2FA service: **enroll** (bind), **verify**, and optional **backup codes**. It does not implement a "send" channel; Stargate (or your login service) calls it for per-user TOTP.

## Base URL

```
http://localhost:8084
```

## Authentication

When `API_KEY` or `HMAC_SECRET` / `HERALD_TOTP_HMAC_KEYS` is set, callers (e.g. Stargate) must authenticate:

- **API Key**: send `X-API-Key` header with the same value.
- **HMAC**: send `X-Timestamp`, `X-Service`, `X-Signature` (and optionally `X-Key-Id`). Signature: `HMAC-SHA256(secret, timestamp + ":" + service + ":" + body)`.

If neither is set, no authentication is required (dev only).

## Endpoints

### Health Check

**GET /healthz**

Returns service and Redis health (via health-kit).

---

### Metrics

**GET /metrics**

Returns Prometheus/OpenMetrics metrics (verify_total, enroll_start_total, enroll_confirm_total). No authentication required for this endpoint.

---

### Start enrollment

**POST /v1/enroll/start**

Generate a TOTP secret and return `enroll_id` and `otpauth_uri` for the frontend to show a QR code.

**Request body:**

| Field   | Type   | Required | Description                                      |
|--------|--------|----------|--------------------------------------------------|
| subject | string | Yes      | User identifier (e.g. `user:12345`).             |
| label   | string | No       | Account name shown in authenticator (default: subject). |

**Response (200):**
```json
{
  "enroll_id": "e_01H...",
  "secret_base32": "JBSWY3DPEHPK3PXP",
  "otpauth_uri": "otpauth://totp/Issuer:label?secret=...&issuer=Issuer&period=30&digits=6"
}
```
When `EXPOSE_SECRET_IN_ENROLL=false`, `secret_base32` is omitted (only `otpauth_uri` for QR).

**Errors:** `400` invalid_request (e.g. subject empty), `429` rate_limited, `500` config_error / internal_error.

---

### Confirm enrollment

**POST /v1/enroll/confirm**

User has scanned the QR and enters one TOTP code to confirm. On success, credential is saved and optional backup codes are returned.

**Request body:**

| Field     | Type   | Required | Description           |
|----------|--------|----------|-----------------------|
| enroll_id| string | Yes      | From enroll/start.    |
| code     | string | Yes      | 6-digit TOTP code.    |

**Response (200):**
```json
{
  "subject": "user:12345",
  "totp_enabled": true,
  "backup_codes": ["ABCD-EFGH", "WXYZ-1234", ...]
}
```

**Errors:** `400` expired (enrollment not found/expired), invalid (code wrong), `500` internal_error.

---

### Verify TOTP

**POST /v1/verify**

Verify a TOTP code (or backup code) for login.

**Request body:**

| Field        | Type   | Required | Description                                |
|-------------|--------|----------|--------------------------------------------|
| subject     | string | Yes      | User identifier.                          |
| code        | string | Yes      | 6-digit TOTP or backup code (e.g. ABCD-EFGH). |
| challenge_id| string | No       | Optional; for replay/audit (one-time use). |

**Response (200):**
```json
{
  "ok": true,
  "subject": "user:12345",
  "amr": ["totp"],
  "issued_at": 1706789012
}
```
When verified via backup code, `amr` is `["totp", "backup_code"]`.

**Error response (4xx):**
```json
{
  "ok": false,
  "reason": "invalid" | "expired" | "replay" | "rate_limited"
}
```

---

### Revoke TOTP

**POST /v1/revoke**

Remove TOTP credential and backup codes for the subject (disenroll).

**Request body:**

| Field   | Type   | Required | Description        |
|--------|--------|----------|--------------------|
| subject| string | Yes      | User identifier.   |

**Response (200):**
```json
{
  "ok": true,
  "subject": "user:12345"
}
```

**Errors:** `400` invalid_request (subject missing), `429` rate_limited.

---

### Status

**GET /v1/status?subject=user:12345**

Check whether the subject has TOTP enabled.

**Response (200):**
```json
{
  "subject": "user:12345",
  "totp_enabled": true
}
```

**Errors:** `400` invalid_request (subject missing), `500` internal_error.
