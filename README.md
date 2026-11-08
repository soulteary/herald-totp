# herald-totp

[![Go Test Coverage](./.github/coverage.svg)](./.github/go-test-report.md) [![Go Report Card](./.github/goreportcard.svg)](./.github/goreportcard-report.md) [![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE) [![Go Version](https://img.shields.io/badge/go-1.27.3+-blue.svg)](https://golang.org)



## v2.0.0 upgrade

The service and SDK use the root module `github.com/soulteary/herald-totp/v2`.
Update SDK imports to `github.com/soulteary/herald-totp/v2/pkg/heraldtotp` and
coordinate HMAC callers with the service. Legacy signatures are rejected.
See [the migration guide](docs/enUS/MIGRATION_V2.md) before upgrading or rolling back.


## Multi-language Documentation

- [English](README.md) | [中文](README.zhCN.md)

TOTP 2FA service for the Herald/Stargate stack: **enroll** (bind), **verify**, and optional **backup codes**. It does not send codes; users generate TOTP in an authenticator app (e.g. Google Authenticator). Stargate calls Herald, which proxies to herald-totp for per-user TOTP instead of a single global secret.

The HTTP server currently uses Fiber v3 and kit packages (exact module versions are recorded in `go.mod`). Building from source requires Go 1.27.3 or later; `go.mod` is the authoritative source for exact dependency versions.

## Core Features

- **Enroll**: `POST /v1/enroll/start` (returns QR content) and `POST /v1/enroll/confirm` (confirm with one TOTP code).
- **Verify**: `POST /v1/verify` (TOTP or backup code), returns `subject`, `amr`, `issued_at`; optional `challenge_id` for replay protection.
- **Revoke**: `POST /v1/revoke` to remove TOTP credential and backup codes for a subject.
- **Status**: `GET /v1/status?subject=...` to check if a user has TOTP enabled.
- **Backup codes**: 10 one-time codes returned on confirm; can be used in verify when the device is lost.
- **Security**: Encrypted secret storage (AES-GCM), rate limiting, atomic one-time consumption of TOTP steps, backup codes, and challenge IDs, plus API key or HMAC auth.
- **Graceful shutdown**: On `SIGINT` or `SIGTERM`, server stops accepting new requests and shuts down with a 10s timeout. Successful shutdown exits 0; shutdown failure (including deadline expiry) logs `shutdown error` and exits 1 from v1.2.8. See the deployment guide for supervisor, retry and rollback requirements.

## Architecture

Stargate orchestrates login and TOTP bind through Herald; herald-totp stores per-user TOTP secrets (encrypted) and backup codes in Redis and performs enroll/verify.

```mermaid
sequenceDiagram
  participant User
  participant Stargate
  participant Herald
  participant HeraldTotp as herald-totp
  participant Redis

  Note over User,Redis: Bind flow (after login)
  User->>Stargate: Open TOTP enroll page
  Stargate->>Herald: POST /v1/totp/enroll/start (subject)
  Herald->>HeraldTotp: POST /v1/enroll/start (subject)
  HeraldTotp->>Redis: Store temp enrollment
  HeraldTotp-->>Herald: enroll_id, otpauth_uri
  Herald-->>Stargate: enroll_id, otpauth_uri
  Stargate-->>User: Show QR code
  User->>Stargate: Enter TOTP code
  Stargate->>Herald: POST /v1/totp/enroll/confirm (enroll_id, code)
  Herald->>HeraldTotp: POST /v1/enroll/confirm (enroll_id, code)
  HeraldTotp->>Redis: Save credential, backup_codes
  HeraldTotp-->>Herald: backup_codes
  Herald-->>Stargate: backup_codes
  Stargate-->>User: Bind done

  Note over User,Redis: Login flow (TOTP step)
  User->>Stargate: Submit TOTP or backup code
  Stargate->>Herald: POST /v1/totp/verify (subject, code)
  Herald->>HeraldTotp: POST /v1/verify (subject, code)
  HeraldTotp->>Redis: Read credential, verify
  HeraldTotp-->>Herald: ok, subject, amr, issued_at
  Herald-->>Stargate: ok, subject, amr, issued_at
  Stargate-->>User: Session created
```

- **Stargate**: ForwardAuth / login and TOTP bind orchestration; calls Herald, which proxies enrollment and verification to herald-totp.
- **herald-totp**: Per-user TOTP secrets (AES-GCM in Redis), enroll/confirm, verify (TOTP or backup code), revoke, status.
- **Redis**: Credentials, enrollment temp state, backup codes, rate limits.

## Protocol

- **POST /v1/enroll/start** – Start enrollment; returns `enroll_id`, `otpauth_uri` (and optionally `secret_base32`).
- **POST /v1/enroll/confirm** – Submit TOTP code to confirm; returns `backup_codes`.
- **POST /v1/verify** – Verify TOTP or backup code; returns `ok`, `subject`, `amr`, `issued_at`.
- **POST /v1/revoke** – Remove TOTP and backup codes for a subject.
- **GET /v1/status?subject=...** – Check if TOTP is enabled for subject.
- **GET /healthz** – Service and Redis health (via [health-kit](https://github.com/soulteary/health-kit)).

## Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Listen port (with or without leading colon) | `:8084` | No |
| `HERALD_TOTP_ENCRYPTION_KEY` | Exact 32-byte AES-256 key for secret encryption | `` | Yes (startup) |
| `API_KEY` | If set, callers must send `X-API-Key` | `` | No |
| `HMAC_SECRET` / `HERALD_TOTP_HMAC_KEYS` | HMAC auth | `` | No |
| `REDIS_ADDR` | Redis address | `localhost:6379` | Yes |
| `EXPOSE_SECRET_IN_ENROLL` | If false, omit `secret_base32` in enroll/start response | `true` | No |
| `LOG_LEVEL` | Log level: trace, debug, info, warn, error | `info` | No |

See [docs/enUS/DEPLOYMENT.md](docs/enUS/DEPLOYMENT.md) for full options.

## Stargate integration

- Enable `HERALD_TOTP_ENABLED=true` on Stargate and configure its Herald connection.
- On Herald, set `HERALD_TOTP_ENABLED=true`, `HERALD_TOTP_BASE_URL=http://herald-totp:8084`, and matching `HERALD_TOTP_API_KEY` or `HERALD_TOTP_HMAC_SECRET`. The request path is Stargate → Herald → herald-totp; Herald owns the backend address and credentials.

## Quick Start

### Build & run (binary)

This is a disposable local Docker example. It generates a fresh key and does not configure a named Redis volume; do not rerun it against existing credentials. For production or existing data, reuse the provisioned key and persistent Redis storage as described in the [deployment guide](docs/enUS/DEPLOYMENT.md). The 15-second runtime grace leaves margin beyond the fixed 10-second application shutdown budget; adjust it for the environment so SIGKILL does not preempt failure reporting.

```bash
export HERALD_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 24)"
export API_KEY="$(openssl rand -hex 32)"
export REDIS_ADDR=localhost:6379
go build -o herald-totp .
./herald-totp
```

Redis must already be reachable at `REDIS_ADDR`. Keep the generated encryption
key stable after credentials have been created; changing it makes existing TOTP
secrets unreadable.

### Run with Docker

```bash
export HERALD_TOTP_ENCRYPTION_KEY="$(openssl rand -base64 24)"
export API_KEY="$(openssl rand -hex 32)"
docker network create herald-totp
docker run -d --name herald-totp-redis --network herald-totp redis:8-alpine
docker build -t herald-totp .
docker run -d --name herald-totp --network herald-totp -p 8084:8084 --stop-timeout=15 \
  -e HERALD_TOTP_ENCRYPTION_KEY -e API_KEY \
  -e REDIS_ADDR=herald-totp-redis:6379 \
  herald-totp
```

Business calls require API-key or HMAC credentials. These examples generate a synthetic `API_KEY`; set `HERALD_TOTP_API_KEY` on Herald to that same value. Requests without valid credentials return 401.

Released images are also available from GHCR. Use an immutable version tag for
deployments, for example `ghcr.io/soulteary/herald-totp:v2.0.3`.

## Documentation

- **[Documentation Index (English)](docs/enUS/README.md)** – [API](docs/enUS/API.md) | [Deployment](docs/enUS/DEPLOYMENT.md) | [Troubleshooting](docs/enUS/TROUBLESHOOTING.md) | [Security](docs/enUS/SECURITY.md)
- **[文档索引（中文）](docs/zhCN/README.md)** – [API](docs/zhCN/API.md) | [部署](docs/zhCN/DEPLOYMENT.md) | [故障排查](docs/zhCN/TROUBLESHOOTING.md) | [安全](docs/zhCN/SECURITY.md)
- **[Changelog and v2.0.0 upgrade notes](CHANGELOG.md)**

## Testing

```bash
go test ./...
```

Coverage:

```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go tool cover -html=coverage.out
```

Lint: `golangci-lint run`.

## Operation

- **Graceful shutdown**: On `SIGINT` or `SIGTERM`, the server stops accepting new requests and shuts down with a 10s timeout. Logs `"shutting down"` and any shutdown error. Successful shutdown exits 0; shutdown failure (including deadline expiry) logs `shutdown error` and exits 1 from v1.2.8. See the deployment guide for supervisor, retry and rollback requirements.
- **Logging**: Structured JSON logs via [logger-kit](https://github.com/soulteary/logger-kit). Set `LOG_LEVEL` to `debug` for more detail.

## License

See [LICENSE](LICENSE) for details.

## HMAC protocol migration

HMAC clients now require operation-bound v2 signatures and one-use nonces. Legacy
signatures are rejected. Upgrade the service and its callers together before
resuming traffic; see [the v2 protocol and deployment order](docs/enUS/SIGNATURE_V2.md).
Authenticated SDK requests reject redirects, and POST routes require JSON.

HMAC service names must contain 1–128 bytes, and explicit key IDs must contain at
most 128 bytes (UTF-8 byte length, not character count). Startup rejects oversized
`HERALD_TOTP_HMAC_KEYS` key IDs; SDK signing rejects oversized identifiers before
sending a request. Omitting the key ID remains supported when exactly one mapped
key is configured. Multiple mapped keys require an explicit key ID.
