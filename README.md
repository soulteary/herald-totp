# herald-totp

TOTP 2FA service for the Herald/Stargate stack: **enroll** (bind), **verify**, and optional **backup codes**. It does not send codes; users generate TOTP in an authenticator app (e.g. Google Authenticator). Stargate calls herald-totp for per-user TOTP instead of a single global secret.

## Features

- **Enroll**: `POST /v1/enroll/start` (returns QR content) and `POST /v1/enroll/confirm` (confirm with one TOTP code).
- **Verify**: `POST /v1/verify` (TOTP or backup code), with optional `challenge_id` for replay protection.
- **Status**: `GET /v1/status?subject=...` to check if a user has TOTP enabled.
- **Backup codes**: 10 one-time codes returned on confirm; can be used in verify when the device is lost.
- **Security**: Encrypted secret storage (AES-GCM), rate limiting, time-step replay protection, API key or HMAC auth.

## Quick start

1. Set a 32-byte encryption key: `export HERALD_TOTP_ENCRYPTION_KEY="your-32-byte-key!!"`
2. Start Redis and herald-totp: `go run .`
3. Configure Stargate with `HERALD_TOTP_ENABLED=true` and `HERALD_TOTP_BASE_URL=http://localhost:8084`.

See [docs/enUS/API.md](docs/enUS/API.md) and [docs/enUS/DEPLOYMENT.md](docs/enUS/DEPLOYMENT.md) for API and deployment details.
