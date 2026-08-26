# herald-totp Deployment

## Requirements

- Go 1.26+
- Redis (for credentials, enrollments, backup codes, rate limits)

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | :8084 | Listen address. |
| LOG_LEVEL | info | Log level. |
| REDIS_ADDR | localhost:6379 | Redis address. |
| REDIS_PASSWORD | | Redis password. |
| REDIS_DB | 0 | Redis DB number. |
| REDIS_TLS_ENABLED | false | Connect to Redis over TLS. |
| REDIS_TLS_SERVER_NAME | | Expected Redis certificate server name. |
| REDIS_TLS_CA_FILE | | Optional PEM CA bundle for Redis. |
| REDIS_TLS_INSECURE_SKIP_VERIFY | false | Disable certificate verification; local diagnostics only. |
| TOTP_ISSUER | Herald | Issuer name in otpauth URI. |
| TOTP_PERIOD | 30 | TOTP period (seconds). |
| TOTP_DIGITS | 6 | TOTP digit count. |
| TOTP_SKEW | 1 | Time step skew (steps). |
| ENROLL_TTL | 10m | Enrollment temp state TTL. |
| HERALD_TOTP_ENCRYPTION_KEY | | **Required** for enroll/verify. 32-byte key for AES-256 (secret encryption). |
| API_KEY | | Optional; service auth. |
| HMAC_SECRET | | Optional; HMAC auth. |
| HERALD_TOTP_HMAC_KEYS | | Optional; JSON map for key rotation. |
| SERVICE_NAME | herald-totp | Service name (e.g. for HMAC). |
| RATE_LIMIT_PER_SUBJECT | 20 | Max requests per subject in a fixed one-hour window starting with the first request. |
| RATE_LIMIT_PER_IP | 30 | Max requests per IP in a fixed one-minute window starting with the first request. |

## Run

```bash
export HERALD_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 24)"
go run .
```

For Redis TLS, enable `REDIS_TLS_ENABLED`, set `REDIS_TLS_SERVER_NAME` to the
certificate name, and optionally provide a private CA bundle through
`REDIS_TLS_CA_FILE`. Keep `REDIS_TLS_INSECURE_SKIP_VERIFY=false` in deployed
environments.

Or use the [.env.example](../.env.example) and run with your process manager / Docker.

## Stargate + Herald integration

1. **Stargate**: set `HERALD_TOTP_ENABLED=true` only (TOTP is via Herald proxy).
2. **Herald**: set `HERALD_TOTP_ENABLED=true`, `HERALD_TOTP_BASE_URL=http://herald-totp:8084`, and `HERALD_TOTP_API_KEY` or `HERALD_TOTP_HMAC_SECRET`. Herald proxies `/v1/totp/*` to herald-totp.
3. Login flow: user enters TOTP code; Stargate calls Herald `/v1/totp/verify`; Herald forwards to herald-totp.
4. Bind flow: user opens Stargate `/totp/enroll` (after login); Stargate calls Herald enroll/start and enroll/confirm; Herald forwards to herald-totp.

## Health

- **GET /healthz**: includes Redis check. Use for readiness/liveness.

## Monitoring

- **GET /metrics**: Prometheus metrics (OpenMetrics format).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| herald_totp_verify_total | Counter | result, reason | TOTP verify attempts (result: success/failure, reason: totp, invalid, replay, rate_limited, backup_code). |
| herald_totp_enroll_start_total | Counter | - | Enroll/start calls. |
| herald_totp_enroll_confirm_total | Counter | result | Enroll/confirm by result (success/failure). |

## Security

- Keep `HERALD_TOTP_ENCRYPTION_KEY` secret and exactly 32 bytes.
- Use API key or HMAC for service-to-service calls.
- Run herald-totp in a private network; do not expose it to the public internet.
