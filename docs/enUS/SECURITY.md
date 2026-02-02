# herald-totp Security Practices

This document describes security considerations and recommendations for herald-totp.

## Encryption Key

- **HERALD_TOTP_ENCRYPTION_KEY** is required for enroll and verify. It must be exactly 32 bytes (256 bits) for AES-256-GCM. Without it, enroll/confirm and verify will fail (config_error).
- Keep this key secret and never commit it to the repository. Use environment variables or a secret manager (e.g. Kubernetes Secrets, HashiCorp Vault). Use `.env` only for local development and ensure `.env` is in `.gitignore`.
- Rotate the key with care: existing encrypted TOTP secrets in Redis will not decrypt with a new key. Plan migration (re-enroll users or decrypt/re-encrypt) if you rotate.

## API Key and HMAC

- When **API_KEY** is set, herald-totp requires the `X-API-Key` header to match for all protected endpoints (enroll, verify, status). Use a strong, unique value and keep it secret.
- Stargate must be configured with the same value as `HERALD_TOTP_API_KEY` so that it sends the key on every request to herald-totp.
- Alternatively, use **HMAC_SECRET** or **HERALD_TOTP_HMAC_KEYS** (JSON map for key rotation). Stargate must sign requests with the same secret and send `X-Timestamp`, `X-Service`, `X-Signature` (and optionally `X-Key-Id`).
- Do not log or expose API key or HMAC secrets. Prefer environment variables or a secret manager over config files committed to source control.

## Production Recommendations

- **Network**: Run herald-totp in a private network. Only Stargate (or your gateway) should call it; do not expose herald-totp directly to the public internet unless behind HTTPS and strict access control.
- **HTTPS**: If herald-totp is reachable over the internet or across untrusted networks, put it behind a reverse proxy (e.g. Traefik, nginx) with TLS. Stargate should use `https://` for `HERALD_TOTP_BASE_URL` in that case.
- **Least privilege**: Run the process with a non-root user; in Docker, use a non-root user in the image if possible.
- **Redis**: Use a dedicated Redis instance or DB index for herald-totp. Enable Redis AUTH and TLS when available. Do not expose Redis to the public.
- **Logging**: Avoid logging request bodies or headers that may contain TOTP codes or backup codes. Structured logs (e.g. subject, result, reason) are sufficient for operations and troubleshooting.

## Summary

- Use **HERALD_TOTP_ENCRYPTION_KEY** (32 bytes) and keep it secret; never in code or committed config.
- Use **API_KEY** or HMAC in production for service-to-service auth; configure Stargate to match.
- Prefer private network and HTTPS in front of herald-totp; do not expose it publicly without protection.
- Protect Redis with auth and TLS where possible.
