# herald-totp API Documentation

herald-totp is a TOTP 2FA service: **enroll** (bind), **verify**, and optional **backup codes**. It does not implement a "send" channel; Stargate (or your login service) calls it for per-user TOTP.

## Base URL

```
http://localhost:8084
```

## Authentication

When `API_KEY` or `HMAC_SECRET` / `HERALD_TOTP_HMAC_KEYS` is set, callers (e.g. Herald, which proxies for Stargate) must authenticate:

- **API Key**: send `X-API-Key` header with the same value.
- **HMAC**: send `X-Timestamp`, `X-Service`, and `X-Signature`. The timestamp is Unix seconds, the body is the exact request-body byte sequence (empty for requests without a body), and the signature is the lowercase hexadecimal encoding of `HMAC-SHA256(secret, timestamp + ":" + service + ":" + body)`. Send `X-Key-Id` whenever `HERALD_TOTP_HMAC_KEYS` contains multiple keys; it may be omitted for a single mapped key.

If neither is set, no authentication is required (dev only).

## Go client

The supported Go client is available at
`github.com/soulteary/herald-totp/pkg/heraldtotp`:

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

For mapped HMAC keys, use `WithHMACSecret` and `WithHMACKeyID`. The default
caller service name is `stargate`; set `Options.Service` when another caller
identity must be included in the signature.

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

Starting another enrollment does not replace an existing credential. Call
`POST /v1/revoke` before intentionally re-enrolling a subject.

**Errors:** `400 invalid_request`, `409 already_enrolled`, `409 enrollment_in_progress`, `429 rate_limited`, `500 config_error`, or `500 internal_error`.

---

### Confirm enrollment

**POST /v1/enroll/confirm**

User has scanned the QR and enters one TOTP code to confirm. On success, credential is saved and optional backup codes are returned.

The credential, backup-code hashes, and temporary enrollment are committed in
one Redis transaction. An `enroll_id` can therefore be confirmed only once,
and backup codes are never returned unless their hashes were persisted.
The TOTP counter used for confirmation is recorded as consumed; wait for a new
TOTP period before using the authenticator for `/v1/verify`.

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
  "backup_codes": ["ABCD-EFGH-JKLM-NPQR", "WXYZ-2345-6789-ABCD", ...]
}
```

**Errors:** `400 expired`, `400 invalid`, `409 already_enrolled`, or `500 internal_error`.

---

### Verify TOTP

**POST /v1/verify**

Verify a TOTP code (or backup code) for login.

**Request body:**

| Field        | Type   | Required | Description                                |
|-------------|--------|----------|--------------------------------------------|
| subject     | string | Yes      | User identifier.                          |
| code        | string | Yes      | 6-digit TOTP or backup code (e.g. ABCD-EFGH-JKLM-NPQR). |
| challenge_id| string | No       | Optional; for replay/audit (one-time use). |

The service records the exact TOTP time step matched within `TOTP_SKEW` and
claims it atomically in Redis. A code accepted from an adjacent skew window
therefore cannot be reused after the server enters that time step. Backup codes
and non-empty `challenge_id` values are also consumed atomically.

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

**Error response:**
```json
{
  "ok": false,
  "reason": "invalid"
}
```

| Status | Reason | Meaning |
|--------|--------|---------|
| `400` | `invalid_request` | Required fields are missing or the JSON body is invalid. |
| `400` | `invalid` | The subject has no enabled TOTP credential. |
| `401` | `invalid` | The supplied TOTP or backup code is invalid. |
| `400` | `replay` | The TOTP counter or `challenge_id` was already consumed. |
| `429` | `rate_limited` | The subject or source IP exceeded its configured limit. |
| `500` | `config_error` | The encryption configuration is invalid. Startup validation normally prevents this state. |
| `500` | `internal_error` | Redis, decryption, or another internal operation failed. |

---

### Revoke TOTP

**POST /v1/revoke**

Remove TOTP credential and backup codes for the subject (disenroll).

The credential and backup codes are removed with one atomic Redis command. A
storage failure returns `500 internal_error` rather than reporting a successful
revocation.

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

**Errors:** `400 invalid_request`, `429 rate_limited`, or `500 internal_error`.

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
