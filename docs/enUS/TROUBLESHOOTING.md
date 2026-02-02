# herald-totp Troubleshooting Guide

This guide helps you diagnose and resolve common issues with herald-totp.

## Table of Contents

- [Enroll or Verify Fails (config_error)](#enroll-or-verify-fails-config_error)
- [401 Unauthorized](#401-unauthorized)
- [Verify Returns invalid / expired / replay / rate_limited](#verify-returns-invalid--expired--replay--rate_limited)
- [Enroll Confirm Returns expired or invalid](#enroll-confirm-returns-expired-or-invalid)
- [Revoke Returns 400 or 429](#revoke-returns-400-or-429)
- [Enroll Response: No secret_base32](#enroll-response-no-secret_base32)
- [Redis Connection Errors](#redis-connection-errors)
- [Stargate Cannot Reach herald-totp](#stargate-cannot-reach-herald-totp)

## Enroll or Verify Fails (config_error)

### Symptoms

- `POST /v1/enroll/start`, `POST /v1/enroll/confirm`, or `POST /v1/verify` returns HTTP 500 with `reason` or message indicating encryption key not configured or invalid.

### Cause

At startup, herald-totp checks that `HERALD_TOTP_ENCRYPTION_KEY` is set and at least 32 bytes. If it is missing or too short, the service logs a warning and enroll/verify operations will fail with config_error.

### Solutions

1. Set `HERALD_TOTP_ENCRYPTION_KEY` to a 32-byte value (e.g. 32 ASCII characters or 64 hex characters decoded to 32 bytes). Restart the process or container.
2. Confirm the variable is actually present in the runtime (no typo in env name; in Docker/Kubernetes it is passed correctly).
3. Check logs at startup: if the key is missing or short, herald-totp logs that enroll/verify will fail.

---

## 401 Unauthorized

### Symptoms

- `POST /v1/enroll/start`, `POST /v1/enroll/confirm`, `POST /v1/verify`, or `GET /v1/status` returns HTTP 401 with `reason: "unauthorized"` or `invalid or missing API key` / HMAC error.

### Cause

herald-totp has `API_KEY` (or HMAC) set, but the request either does not send the required header(s) or sends a value that does not match.

### Solutions

1. **If you use API Key**  
   - Set `API_KEY` on herald-totp.  
   - Set `HERALD_TOTP_API_KEY` on Stargate to the same value so Stargate sends it in `X-API-Key`.  
   - Ensure no proxy or gateway strips the `X-API-Key` header.

2. **If you use HMAC**  
   - Set `HMAC_SECRET` or `HERALD_TOTP_HMAC_KEYS` on herald-totp.  
   - Configure Stargate with the same secret (or key map) and ensure it signs requests with `X-Timestamp`, `X-Service`, `X-Signature`.  
   - Check that clock skew between Stargate and herald-totp is within the accepted window (e.g. 60 seconds).

3. **If you do not want auth in dev**  
   - Leave `API_KEY` and HMAC unset on herald-totp (and do not set Stargate auth for herald-totp). Use only in non-production environments.

---

## Verify Returns invalid / expired / replay / rate_limited

### Symptoms

- `POST /v1/verify` returns 200 with `ok: false` and `reason: "invalid"`, `"expired"`, `"replay"`, or `"rate_limited"`.

### Causes and Solutions

- **invalid**: The TOTP code or backup code is wrong, or the subject has no TOTP enrolled. Ensure the user enters the current 6-digit code from their authenticator app, or a valid unused backup code. Check that the subject (e.g. `user:12345`) matches the enrolled user.
- **expired**: Not typically used for verify; more common for enroll (enroll_id expired). For verify, ensure the user’s TOTP secret is still stored (status returns totp_enabled: true).
- **replay**: The same challenge_id (or same code in a time window) was already used. Ensure each login attempt uses a new challenge_id or omit it; do not reuse a challenge_id after successful verify.
- **rate_limited**: Per-subject or per-IP rate limit exceeded. Wait for the rate limit window to reset, or adjust `RATE_LIMIT_PER_SUBJECT` / `RATE_LIMIT_PER_IP` if appropriate for your environment.

---

## Enroll Confirm Returns expired or invalid

### Symptoms

- `POST /v1/enroll/confirm` returns 400 with `reason: "expired"` or `"invalid"`.

### Causes and Solutions

- **expired**: The enroll_id from `POST /v1/enroll/start` has expired (default TTL 10m). The user must start enrollment again: call enroll/start and have the user scan the new QR code, then submit the new code to enroll/confirm.
- **invalid**: The 6-digit TOTP code submitted does not match the current TOTP for the temporary secret. Ensure the user’s authenticator app time is in sync and they enter the current code. Check that TOTP period (default 30s) and skew are consistent.

---

## Revoke Returns 400 or 429

### Symptoms

- `POST /v1/revoke` returns 400 with `reason: "invalid_request"` (e.g. subject required), or 429 with `reason: "rate_limited"`.

### Causes and Solutions

- **400 invalid_request**: Request body must include `subject` (user identifier). Send `{"subject": "user:12345"}`.
- **429 rate_limited**: Per-subject or per-IP limit exceeded. Wait for the window to reset or adjust `RATE_LIMIT_PER_SUBJECT` / `RATE_LIMIT_PER_IP`.

---

## Enroll Response: No secret_base32

### Symptoms

- `POST /v1/enroll/start` returns 200 but the response does not contain `secret_base32`, only `enroll_id` and `otpauth_uri`.

### Cause

`EXPOSE_SECRET_IN_ENROLL` is set to `false` (or `0` / `no`). This is intentional for production to avoid exposing the raw secret; only the `otpauth_uri` is provided for QR code generation.

### Solutions

- If you need the secret (e.g. for manual entry), set `EXPOSE_SECRET_IN_ENROLL=true` (default). Use only in trusted or dev environments.
- If you want to hide the secret, keep it `false` and use only `otpauth_uri` for the QR code.

---

## Redis Connection Errors

### Symptoms

- Startup fails or requests fail with Redis connection errors; health check returns unhealthy.

### Solutions

1. Verify `REDIS_ADDR`, `REDIS_PASSWORD`, and `REDIS_DB` are correct and that Redis is reachable from the herald-totp network (e.g. same Docker network, or correct host/port).
2. If Redis is protected by auth, set `REDIS_PASSWORD`. If Redis uses TLS, ensure the client configuration (if supported by your Redis driver) is set.
3. Check Redis server logs and resource limits (memory, connections). Ensure herald-totp has enough connections (default pool size).

---

## Stargate Cannot Reach herald-totp

### Symptoms

- Stargate login or TOTP enroll flow fails with connection refused, timeout, or 5xx when calling herald-totp.

### Solutions

1. Confirm `HERALD_TOTP_BASE_URL` on Stargate points to the correct herald-totp URL (e.g. `http://herald-totp:8084` in Docker Compose).
2. Ensure herald-totp is running and listening on the expected port (default 8084). Check `PORT` env and container port mapping.
3. If Stargate and herald-totp are in different networks, ensure DNS or service discovery resolves the hostname and that firewall/security groups allow traffic on the port.
4. If using HTTPS, ensure the certificate is valid and Stargate trusts it (or use `insecure_skip_verify` only for dev).
