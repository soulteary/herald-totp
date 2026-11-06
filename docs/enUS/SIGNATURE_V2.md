# Operation-bound request authentication

HMAC clients and the TOTP service must use the v2 wire protocol together. Legacy
`timestamp:service:body` signatures are rejected. API-key-only clients continue
to work. An invalid or incomplete HMAC request never falls back to an API key.
When both credentials are configured, the SDK sends HMAC without the bearer key.

Each signed request includes `X-Signature-Version: v2`, `X-Timestamp` (Unix
seconds), `X-Service`, `X-Nonce` (16 random bytes encoded as 32 lowercase hex
characters), and `X-Signature` (lowercase HMAC-SHA256 hex). `X-Key-Id` selects a
mapped key; omitting it is supported only for the existing single-key case.

The canonical input contains these fields in order: version, HTTP method,
escaped path, raw query, wire key ID, timestamp, service, nonce, and the hex
SHA-256 of the raw body. Each field is encoded as its byte length in decimal,
a newline, the field bytes, and a newline. Use `heraldtotp.SignRequest` rather
than duplicating the encoding. Signing errors must stop the outbound request.

The server accepts timestamps within 60 seconds and retains consumed nonces for
150 seconds. Replay state binds the actual secret, service, and nonce, so key-ID
aliases cannot create separate replay windows. A nonce-store failure returns
503; it does not allow the request. POST routes accept `application/json` only
(with optional media-type parameters), before authentication or nonce consumption.
This prevents identical signed bytes being interpreted as form data instead.

## Deployment order

Pause callers and drain in-flight TOTP operations. Deploy the new service and
upgrade every HMAC client, including Herald's proxy, before resuming traffic.
There is no production switch to restore legacy signatures. API-key deployments
can migrate independently, but the SDK still rejects redirects. Keep a verified
TLS transport and distinct service credentials; HMAC does not encrypt payloads.

The authenticated SDK rejects redirects instead of forwarding credentials or
request bodies to another endpoint. Configure the final service origin.
