# herald-totp Deployment

## Requirements

- Go 1.26+
- Redis (for credentials, enrollments, backup codes, rate limits)

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | :8084 | Non-empty listen port, with or without a leading colon. |
| LOG_LEVEL | info | Log level. |
| REDIS_ADDR | localhost:6379 | Non-empty Redis address. |
| REDIS_PASSWORD | | Redis password. |
| REDIS_DB | 0 | Redis DB number; must be non-negative. |
| REDIS_TLS_ENABLED | false | Connect to Redis over TLS. |
| REDIS_TLS_SERVER_NAME | | Expected Redis certificate server name; requires `REDIS_TLS_ENABLED=true`. |
| REDIS_TLS_CA_FILE | | Optional PEM CA bundle; requires `REDIS_TLS_ENABLED=true`. |
| REDIS_TLS_INSECURE_SKIP_VERIFY | false | Disable certificate verification; diagnostics only and requires TLS to be enabled. |
| TOTP_ISSUER | Herald | Non-empty issuer name in the otpauth URI. |
| TOTP_PERIOD | 30 | TOTP period in seconds; `1` to `300`. |
| TOTP_DIGITS | 6 | TOTP digit count; `6` or `8`. |
| TOTP_SKEW | 1 | Time-step skew; `0` to `10` steps. |
| ENROLL_TTL | 10m | Positive enrollment temporary-state TTL. |
| HERALD_TOTP_ENCRYPTION_KEY | | **Required at startup**; exactly 32 bytes for AES-256-GCM. |
| API_KEY | | Optional; service auth. |
| HMAC_SECRET | | Optional; HMAC auth. |
| HERALD_TOTP_HMAC_KEYS | | Optional non-empty JSON map for key rotation; key IDs and secrets must be non-empty. |
| SERVICE_NAME | herald-totp | Service name reported by the health endpoint. |
| EXPOSE_SECRET_IN_ENROLL | true | Include `secret_base32` in enroll/start. Set to `false` in production when manual entry is not required. |
| RATE_LIMIT_PER_SUBJECT | 20 | Positive request limit per subject in a fixed one-hour window starting with the first request. |
| RATE_LIMIT_PER_IP | 30 | Positive request limit per IP in a fixed one-minute window starting with the first request. |

All validation failures are reported together and the process exits before
opening the listen socket or initializing Redis.

## Run

```bash
export HERALD_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 24)"
go run .
```

For Redis TLS, enable `REDIS_TLS_ENABLED`, set `REDIS_TLS_SERVER_NAME` to the
certificate name, and optionally provide a private CA bundle through
`REDIS_TLS_CA_FILE`. Keep `REDIS_TLS_INSECURE_SKIP_VERIFY=false` in deployed
environments.

Or copy [`.env.example`](../../.env.example), replace every secret placeholder,
and load it with your process manager or container runtime. The example file is
not production configuration.

## Release artifacts

Each release publishes Linux, macOS, and Windows binaries plus
`checksums.txt`. Multi-architecture container images are published to GHCR:

```bash
docker pull ghcr.io/soulteary/herald-totp:v1.0.0
```

Use the full version tag for reproducible deployments. The release workflow
also publishes SemVer aliases without the leading `v`.

## Stargate + Herald integration

1. **Stargate**: set `HERALD_TOTP_ENABLED=true` only (TOTP is via Herald proxy).
2. **Herald**: set `HERALD_TOTP_ENABLED=true`, `HERALD_TOTP_BASE_URL=http://herald-totp:8084`, and `HERALD_TOTP_API_KEY` or `HERALD_TOTP_HMAC_SECRET`. Herald proxies `/v1/totp/*` to herald-totp.
3. Login flow: user enters TOTP code; Stargate calls Herald `/v1/totp/verify`; Herald forwards to herald-totp.
4. Bind flow: user opens Stargate `/totp/enroll` (after login); Stargate calls Herald enroll/start and enroll/confirm; Herald forwards to herald-totp.

## Health

- **GET /healthz**: includes a Redis dependency check. Use it as a readiness
  probe. Do not use it as a Kubernetes liveness probe: a Redis outage would
  otherwise restart healthy application processes. The service does not
  currently expose a separate dependency-free HTTP liveness endpoint.

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
- The official container runs as the unprivileged user and group `10001:10001`.
