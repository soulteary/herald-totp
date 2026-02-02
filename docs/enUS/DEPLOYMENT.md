# herald-totp Deployment

## Requirements

- Go 1.25+
- Redis (for credentials, enrollments, backup codes, rate limits)

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | :8084 | Listen address. |
| LOG_LEVEL | info | Log level. |
| REDIS_ADDR | localhost:6379 | Redis address. |
| REDIS_PASSWORD | | Redis password. |
| REDIS_DB | 0 | Redis DB number. |
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
| RATE_LIMIT_PER_SUBJECT | 20 | Max requests per subject per hour. |
| RATE_LIMIT_PER_IP | 30 | Max requests per IP per minute. |

## Run

```bash
export HERALD_TOTP_ENCRYPTION_KEY="your-32-byte-secret-key-here!!"
go run .
```

Or use the [.env.example](../.env.example) and run with your process manager / Docker.

## Stargate integration

1. Set Stargate env: `HERALD_TOTP_ENABLED=true`, `HERALD_TOTP_BASE_URL=http://herald-totp:8084`, and `HERALD_TOTP_API_KEY` or `HERALD_TOTP_HMAC_SECRET`.
2. Login flow: when user chooses OTP, Stargate calls herald-totp `POST /v1/verify` with subject and code.
3. Bind flow: user opens Stargate `/totp/enroll` (after login); Stargate calls herald-totp enroll/start and enroll/confirm.

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

- Keep `HERALD_TOTP_ENCRYPTION_KEY` secret and at least 32 bytes.
- Use API key or HMAC for service-to-service calls.
- Run herald-totp in a private network; do not expose it to the public internet.
