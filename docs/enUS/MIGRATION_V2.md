# Upgrading to v2.0.0

v2.0.0 versions the service and Go SDK together. The root module is now
`github.com/soulteary/herald-totp/v2`; the client package is
`github.com/soulteary/herald-totp/v2/pkg/heraldtotp`. Existing `/v1/status`,
`/v1/verify`, enrollment, and revoke HTTP routes retain their paths. The module
major, HMAC wire version, and HTTP route version are separate version identifiers.

## Changes since v1.2.8

HMAC authentication now uses the [operation-bound v2 protocol](SIGNATURE_V2.md).
Legacy body-only signatures are rejected. Redis atomically consumes nonces;
a replay-store outage returns 503. Incomplete or invalid HMAC attempts cannot
fall back to an API key. A client configured with both credentials sends HMAC
only. Service names contain 1–128 bytes and explicit key IDs at most 128 bytes,
measured as UTF-8 bytes. Mapped key IDs are checked at startup. SDK signing errors
stop requests before sending or changing authentication headers.

POST endpoints require `application/json` (optional media-type parameters are
accepted). Authenticated SDK requests reject redirects. Configure the final
service URL and verified TLS transport. HMAC authenticates content but does not
encrypt it. Single mapped keys can still omit the key ID; multiple keys require
an explicit ID. API-key-only authentication remains available.

## Upgrade

1. Preserve the current Redis dataset and encryption key. Record the currently
   deployed service image and caller versions. Do not regenerate the encryption
   key or substitute an empty Redis instance during replacement.
2. Pause HMAC callers and drain in-flight enrollment and verification operations.
   Resolve uncertain operation results before retrying them.
3. Deploy `ghcr.io/soulteary/herald-totp:v2.0.0` with the existing Redis and key.
   Grant the Redis commands needed for nonce storage alongside credential storage.
4. Upgrade every caller, including Herald's TOTP proxy. Run
   `go get github.com/soulteary/herald-totp/v2@v2.0.0` and replace the SDK import:

   ```go
   import "github.com/soulteary/herald-totp/v2/pkg/heraldtotp"
   ```

   Use `heraldtotp.SignRequest` or the v2 SDK, handle signing errors, send JSON,
   and set valid service/key identifiers. Remove the old root-module dependency
   once its imports are gone (`go mod tidy`).
5. Check service readiness, verify a correctly signed operation, and confirm that
   reusing its nonce and changing its target are rejected. Resume callers only
   after all HMAC clients and service instances use the v2 protocol.

An API-key-only deployment can replace clients and service independently, subject
to JSON and redirect requirements. A mixed HMAC deployment using legacy clients
is unsupported; there is no switch to re-enable the old signature protocol.

Credential records, encrypted secrets, and backup-code formats are unchanged
relative to v1.2.8. Previously documented enrollment-index restrictions still
apply when upgrading from older versions; see [security guidance](SECURITY.md).
This release does not require users to re-enroll their TOTP credentials.

## Rollback and releases

A rollback must coordinate HMAC service and caller versions. Rolling back only
one side causes authentication failures, and restoring v1.2.8 restores its
request-binding and replay weaknesses. Preserve the Redis dataset and encryption
key throughout rollback; do not interpret a failed response as proof that a
state-changing request was not committed.

The root module uses `/v2` for both service and SDK. Release automation accepts
stable `v2.x.y` tags only after checking the module path. Formal releases publish
versioned binaries and container tags, including `2`, `2.0`, `2.0.0`, `v2.0.0`,
and `latest` for v2.0.0. Pin the full version in deployments; do not rely on mutable
major or latest tags when coordinating an upgrade. This workflow does not publish
release candidates.


## Patch upgrade from v2.0.0 to v2.0.1

v2.0.1 adds enrollment confirmation to the existing subject/hour and
peer-IP/minute quotas. Review both limits before switching traffic. Start and
confirmation share counters with verification and revocation; reserve at least
two subject requests for the successful enrollment flow, plus other operations
and failed attempts. A subject limit of one blocks confirmation after start
until the hourly reset, and the enrollment may expire first. Requests through a
shared Herald proxy can share the same upstream peer-IP quota.

Unknown enrollment IDs count against the IP budget. Valid records use their
stored subject, never a client-provided subject. Each confirmation counts the IP
once and checks quotas before secret decryption or code validation. Exhaustion
returns `429/rate_limited`. A Redis quota failure rejects the request without
consuming the enrollment or creating a credential. Successful HTTP payloads,
HMAC v2 and the Go `/v2` import path remain unchanged.

Keep Redis, quota windows, nonce/replay state and the original encryption key
through upgrade and rollback. No data conversion is required between these two
patch versions. Do not flush counters or pending records to bypass a 429.
Configure the client to retain its enrollment context for retry, while respecting
the enrollment's existing expiry. Older proxies may mask 429 as a generic error;
Herald v1.4.1 preserves this confirmation response as `429/rate_limited`.

Rolling back to v2.0.0 removes the confirmation quota fix. The same persisted
state remains readable, but that rollback restores the unbounded confirmation
path. Rollback to a pre-v2 release also loses the authentication safeguards and
must follow the major-version restrictions above; do not downgrade it as an
independent response to a gateway failure.

## Credential-snapshot commit guard (unreleased)

The verification commit guard added after v2.0.1 compares the enabled credential
and its validation parameters with the snapshot used to validate the code. A
changed record rejects the commit without advancing that record or claiming the
challenge. Concurrent counter progress on the same credential remains supported.
There is no credential format, key, HTTP success payload or SDK migration.

Replace all TOTP service instances to obtain this guard. Mixed older instances
retain the earlier commit behavior; rollback restores it. Preserve the existing
Redis dataset, encryption key and replay state. This does not cancel requests
that committed before a credential change.
