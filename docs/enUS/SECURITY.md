# herald-totp Security Practices

This document describes security considerations and recommendations for herald-totp.

## Encryption Key

- **HERALD_TOTP_ENCRYPTION_KEY** is required and must be exactly 32 bytes (256 bits) for AES-256-GCM. The service refuses to start without a valid key.
- Keep this key secret and never commit it to the repository. Use environment variables or a secret manager (e.g. Kubernetes Secrets, HashiCorp Vault). Use `.env` only for local development and ensure `.env` is in `.gitignore`.
- Rotate the key with care: existing encrypted TOTP secrets in Redis will not decrypt with a new key. Plan migration (re-enroll users or decrypt/re-encrypt) if you rotate.

## API Key and HMAC

- For API-key authentication, herald-totp requires a matching `X-API-Key` on protected endpoints (enroll, verify, revoke, and status). Use a strong, unique value and keep it secret.
- Herald must be configured with the same value as `HERALD_TOTP_API_KEY` so that it sends the key on every request to herald-totp.
- Alternatively, use **HMAC_SECRET** or **HERALD_TOTP_HMAC_KEYS** (JSON map for key rotation). Herald must sign requests with the same secret and send `X-Signature-Version: v2`, `X-Timestamp`, `X-Service`, `X-Nonce`, `X-Signature`, and `X-Key-Id` when the map contains multiple keys. `X-Key-Id` may be omitted only for a single mapped key.
- Do not log or expose API key or HMAC secrets. Prefer environment variables or a secret manager over config files committed to source control.

## Production Recommendations

- **Runtime policy**: The current explicit-nonce AES-GCM encoding is unsupported under Go `GODEBUG=fips140=only`; encryption and decryption return errors. This is an existing operating limit; the tests cover the [Go GCM policy rejection](https://go.dev/src/crypto/cipher/gcm.go).
- **Network**: Run herald-totp in a private network. Only Herald (or another authorized service) should call it; do not expose herald-totp directly to the public internet unless behind HTTPS and strict access control.
- **HTTPS**: If herald-totp is reachable over the internet or across untrusted networks, put it behind a reverse proxy (e.g. Traefik, nginx) with TLS. Herald should use `https://` for `HERALD_TOTP_BASE_URL` in that case.
- **Least privilege**: Run the process with a non-root user. The official container is configured as the numeric user and group `10001:10001`.
- **Redis**: Use a dedicated Redis instance or DB index for herald-totp. Enable Redis AUTH and TLS when available. Do not expose Redis to the public.
- **Logging**: Avoid logging request bodies or headers that may contain TOTP codes or backup codes. Structured logs (e.g. subject, result, reason) are sufficient for operations and troubleshooting.
- **Enrollment response**: Set `EXPOSE_SECRET_IN_ENROLL=false` in production when manual secret entry is not required. The `otpauth_uri` still contains the secret and must be handled as sensitive data.
- **Metrics**: `/metrics` is intentionally unauthenticated. Restrict it at the network or reverse-proxy layer and do not expose it publicly.

## Replay Protection

- The exact TOTP counter matched inside the configured skew window is claimed atomically in Redis. This prevents two concurrent requests from accepting the same code and prevents a future-window code from being accepted again when that window becomes current.
- Backup codes are updated with an optimistic Redis transaction, so only one concurrent request can consume a code.
- A non-empty `challenge_id` is claimed in the same optimistic Redis transaction as the matched TOTP counter or backup-code consumption; reuse returns the `replay` reason.
- Replay guarantees depend on Redis availability and consistency. Avoid splitting a subject's TOTP traffic across independent Redis datasets.
- Enrollment confirmation commits the credential, backup-code hashes, and enrollment consumption in one Redis transaction. Revocation atomically deletes the credential, backup codes, enrollment index and its active pending enrollment.
- Rate-limit counters keep the expiry established by the first request in each window; later requests cannot indefinitely extend a blocked counter.

## Summary

- Use **HERALD_TOTP_ENCRYPTION_KEY** (32 bytes) and keep it secret; never in code or committed config.
- Use **API_KEY** or HMAC in production for service-to-service auth; configure Herald to match.
- Prefer private network and HTTPS in front of herald-totp; do not expose it publicly without protection.
- Protect Redis with auth and TLS where possible.

## Bound signatures

Use the [v2 request protocol](SIGNATURE_V2.md). Every HMAC operation requires a
fresh nonce and a signature bound to its exact target. Replay-store failures
reject the request. Requests with invalid HMAC never fall back to a supplied
API key. POST routes accept JSON only. Upgrade the service and clients together.
