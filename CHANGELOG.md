# Changelog

All notable changes to herald-totp are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Dates use the
`YYYY-MM-DD` format.

## [Unreleased]

## [1.2.8] - 2026-11-02

### Fixed

- Exit with status 1 when HTTP shutdown fails, including a deadline, instead of
  returning success after the existing `shutdown error` warning. Normal drain
  still exits 0. API/configuration, warning fields/level and stored records are
  unchanged; review supervisor restart policy and reconcile uncertain operations
  before retrying. Rollback restores the old failure exit status.
- Add a real subprocess regression that requires the shutdown diagnostic and
  exit status 1, with standard Go child coverage instrumentation.

## [1.2.7] - 2026-11-02

### Tests

- Verify real startup failures and the shutdown deadline for an enrollment
  blocked on entropy. Cover unavailable random sources without committing a
  credential or consuming enrollment state.
- Verify TLS trust fallback, Redis authentication failures, corrupt/rebound
  enrollment records and a challenge claimed after verification prechecks.
- Verify existing rejection of explicit-nonce GCM under strict FIPS runtime
  policy in an isolated subprocess.
- Raise the CI coverage floor from 95% to 98%; Linux race tests reach 98.25%
  total statement coverage while retaining defensive production error paths.
  API, configuration, stored records and replay guarantees are unchanged.

## [1.2.6] - 2026-11-02

### Tests

- Verify startup and graceful shutdown, enrollment conflicts, persistence failures,
  transaction contention exhaustion, Redis TLS trust and client error contracts.
- Test a real Redis commit followed by a simulated lost acknowledgement: retries
  retain the committed verification counter and challenge and reject reuse.
- Enforce at least 95% total statement coverage without excluding production code.
- Correct current Go and kit module requirements in English and Chinese guides.


### Changed

- Update `cli-kit` to v1.9.3, `health-kit/v4` to v4.0.5,
  `logger-kit/v3` and `metrics-kit/v3` to v3.0.4, `middleware-kit/v3`
  to v3.0.4, `redis-kit` to v1.8.1, `secure-kit/v2` to v2.1.3 and
  `version-kit/v4` to v4.0.3; refresh the required transitive graph and checksums.

### Upgrading from v1.2.5

- Pin the binary or container to v1.2.6. HTTP routes, HMAC authentication,
  environment variables and stored Redis credential formats remain compatible;
  no data migration or encryption-key change is required.
- Keep the existing encryption key and Redis data. The Redis integration tests
  verify enrollment, replay prevention, single-use backup codes, expiry and
  ambiguous commit acknowledgements against a real server.

## [1.2.5] - 2026-10-22

### Changed

- Require Go 1.27.3 and align build images and CI toolchains.
- Update compatible Go dependencies and published Kit versions; refresh module checksums.
- Preserve the project toolchain after quality report generation.


## [1.2.3] - 2026-09-21

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

[Unreleased]: https://github.com/soulteary/herald-totp/compare/v1.2.8...HEAD
[1.2.8]: https://github.com/soulteary/herald-totp/compare/v1.2.7...v1.2.8
[1.2.7]: https://github.com/soulteary/herald-totp/compare/v1.2.6...v1.2.7
[1.2.6]: https://github.com/soulteary/herald-totp/compare/v1.2.5...v1.2.6
[1.2.5]: https://github.com/soulteary/herald-totp/compare/v1.2.4...v1.2.5
[1.2.3]: https://github.com/soulteary/herald-totp/compare/v1.2.2...v1.2.3
[1.0.0]: https://github.com/soulteary/herald-totp/compare/v0.6.0...v1.0.0
