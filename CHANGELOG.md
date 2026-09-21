# Changelog

All notable changes to herald-totp are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Dates use the
`YYYY-MM-DD` format.

## [Unreleased]

### Changed

- Upgraded every soulteary kit dependency to its latest major version:
  `health-kit` v2.3.0 to v4.0.0, `logger-kit` v2.3.0 to v3.0.0, `metrics-kit`
  v2.2.0 to v3.0.0, `middleware-kit` v2.2.0 to v3.0.0, `secure-kit` v1.6.0 to
  v2.1.0, `version-kit` v2.2.0 to v4.0.0, and `redis-kit` v1.6.0 to v1.7.0.
  A Go major version is a distinct import path, so each of these changed the
  module path as well as the version.
- Each kit moved its Fiber support out of the root package and into a
  `fiberadapter` subpackage, so importing a kit's root package no longer links
  Fiber and fasthttp. The router now calls `loggerfiber.Middleware`,
  `healthfiber.Handler`, `metricsfiber.HandlerFor` and `mwfiber.CombinedAuth`,
  and the Redis health check moved to the `redisprobe` subpackage of
  `health-kit`. The Fiber-typed hooks moved with them, so the logger and
  auth configurations are now the framework-neutral config embedded in the
  adapter's own config type.
- Build scripts inject the version through `version-kit/v4` rather than
  `version-kit/v2`. A build left on the old path still compiles, but reports
  its version as `dev`.

The service contract is unchanged: routes, authentication outcomes, `/healthz`
and `/metrics` responses, log fields and metric names are all as they were.

## [1.0.0] - 2026-08-26

The first stable release defines the HTTP API, Redis-backed credential model,
and Go client as the supported v1 contract.

### Added

- Redis TLS support, including server-name verification and custom CA bundles.
- Multi-key HMAC authentication with deterministic `X-Key-Id` selection.
- Atomic replay protection for TOTP counters, backup codes, and challenge IDs.
- Centralized startup validation for encryption, Redis, TOTP, TLS, enrollment,
  and rate-limit configuration.
- Multi-platform release binaries, SHA-256 checksums, and multi-architecture
  container images.

### Changed

- Enrollment confirmation consumes the TOTP counter used to confirm the
  credential. The same code cannot immediately be reused for verification.
- Starting a new enrollment no longer replaces an existing credential. Revoke
  the credential before enrolling the subject again.
- Newly generated backup codes use the `XXXX-XXXX-XXXX-XXXX` format and carry
  approximately 80 bits of entropy.
- `HERALD_TOTP_ENCRYPTION_KEY` is validated at startup and must be exactly 32
  bytes.
- Multiple HMAC keys require an explicit `X-Key-Id`; a single mapped key remains
  unambiguous without the header.
- The Go client preserves the complete verify response (`subject`, `amr`, and
  `issued_at`) and supports HMAC key IDs.
- The container runs as the unprivileged numeric user and group `10001:10001`.

### Upgrade notes from v0.6.0

1. Set `HERALD_TOTP_ENCRYPTION_KEY` to the existing 32-byte encryption key
   before starting the service. Changing it without migrating credentials makes
   existing TOTP secrets unreadable.
2. Check all environment variables against the validation ranges in
   `docs/enUS/DEPLOYMENT.md` or `docs/zhCN/DEPLOYMENT.md`.
3. When `HERALD_TOTP_HMAC_KEYS` contains multiple entries, configure callers to
   send the matching `X-Key-Id`.
4. Update clients to handle enrollment conflicts (`409 already_enrolled` and
   `409 enrollment_in_progress`) and the documented verify status codes.
5. Do not retry the TOTP code used for enrollment confirmation as an immediate
   login verification code; wait for a new TOTP period.

Existing credential and backup-code records keep their Redis key and JSON
formats. Backup codes issued before v1.0.0 remain valid until consumed or the
credential is revoked; only newly generated codes use the longer format.

[Unreleased]: https://github.com/soulteary/herald-totp/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/soulteary/herald-totp/compare/v0.6.0...v1.0.0
