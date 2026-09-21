package router

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v3"
	logger "github.com/soulteary/logger-kit/v3"

	"github.com/soulteary/herald-totp/internal/config"
)

func TestSetup(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	oldAddr := config.RedisAddr
	oldPass := config.RedisPassword
	oldDB := config.RedisDB
	config.RedisAddr = mr.Addr()
	config.RedisPassword = ""
	config.RedisDB = 0
	defer func() {
		config.RedisAddr = oldAddr
		config.RedisPassword = oldPass
		config.RedisDB = oldDB
	}()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New()
	st, err := Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if st == nil {
		t.Fatal("Store is nil")
	}

	// Health check
	req := httptest.NewRequest("GET", "/healthz", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestSetup_RedisTLSConfigError(t *testing.T) {
	oldEnabled := config.RedisTLSEnabled
	oldCAFile := config.RedisTLSCAFile
	config.RedisTLSEnabled = true
	config.RedisTLSCAFile = filepath.Join(t.TempDir(), "missing-ca.pem")
	defer func() {
		config.RedisTLSEnabled = oldEnabled
		config.RedisTLSCAFile = oldCAFile
	}()

	log := logger.New(logger.Config{Level: logger.Disabled})
	if _, err := Setup(fiber.New(), log); err == nil {
		t.Fatal("Setup with missing Redis TLS CA: expected error")
	}
}

func TestSetup_RevokeRoute(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	oldAddr := config.RedisAddr
	config.RedisAddr = mr.Addr()
	defer func() { config.RedisAddr = oldAddr }()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New()
	_, err = Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// POST /v1/revoke with empty body: 400 (subject required) when no auth, or 401 when auth required
	req := httptest.NewRequest("POST", "/v1/revoke", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /v1/revoke status = %d, want 400 or 401", resp.StatusCode)
	}
}

func TestSetup_StatusRoute(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	oldAddr := config.RedisAddr
	config.RedisAddr = mr.Addr()
	defer func() { config.RedisAddr = oldAddr }()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New()
	_, err = Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// GET /v1/status without subject: 400 when no auth, or 401 when auth required
	req := httptest.NewRequest("GET", "/v1/status", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/status status = %d, want 400 or 401", resp.StatusCode)
	}
}

// --- CombinedAuth regression coverage ---
//
// middleware-kit v3 reworked how CombinedAuth decides a request: mTLS is now
// actually attempted rather than being skipped by a guard that never held.
// This service configures no MTLSConfig, so every request below travels the
// HMAC and API-key paths -- these tests pin that down.

// authTestBody carries no subject, so a request that authenticates reaches the
// revoke handler and is answered 400; one that does not is answered 401. That
// difference is what every assertion here reads.
const authTestBody = `{}`

// newAuthTestApp builds the real router against miniredis. CombinedAuth reads
// config.APIKey and config.AllowNoAuth() at setup time, so both are installed
// before Setup runs.
func newAuthTestApp(t *testing.T, apiKey, hmacSecret string) *fiber.App {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	oldAddr, oldAPIKey, oldHMAC := config.RedisAddr, config.APIKey, config.HMACSecret
	config.RedisAddr = mr.Addr()
	config.APIKey = apiKey
	config.HMACSecret = hmacSecret
	t.Cleanup(func() {
		config.RedisAddr = oldAddr
		config.APIKey = oldAPIKey
		config.HMACSecret = oldHMAC
	})

	app := fiber.New()
	if _, err := Setup(app, logger.New(logger.Config{Level: logger.Disabled})); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return app
}

// postRevoke sends POST /v1/revoke through the auth middleware and reports the
// status. headers is applied to the request before it is sent.
func postRevoke(t *testing.T, app *fiber.App, headers map[string]string) int {
	t.Helper()

	req := httptest.NewRequest("POST", "/v1/revoke", bytes.NewReader([]byte(authTestBody)))
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode
}

// signHMAC reproduces middleware-kit's default signature encoding,
// "timestamp:service:body" -- the same bytes pkg/heraldtotp's client signs.
func signHMAC(timestamp, service, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + ":" + service + ":" + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacHeaders(timestamp, service, signature string) map[string]string {
	h := map[string]string{
		"X-Timestamp": timestamp,
		"X-Signature": signature,
	}
	if service != "" {
		h["X-Service"] = service
	}
	return h
}

func TestSetup_AuthHMAC(t *testing.T) {
	const secret = "hmac-test-secret"
	app := newAuthTestApp(t, "", secret)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{
			name:    "valid signature",
			headers: hmacHeaders(now, "", signHMAC(now, "", authTestBody, secret)),
			want:    http.StatusBadRequest,
		},
		{
			name:    "valid signature with service",
			headers: hmacHeaders(now, "herald", signHMAC(now, "herald", authTestBody, secret)),
			want:    http.StatusBadRequest,
		},
		{
			name:    "signature from the wrong secret",
			headers: hmacHeaders(now, "", signHMAC(now, "", authTestBody, "not-the-secret")),
			want:    http.StatusUnauthorized,
		},
		{
			name:    "tampered signature",
			headers: hmacHeaders(now, "", "deadbeef"),
			want:    http.StatusUnauthorized,
		},
		{
			name:    "signature bound to a different body",
			headers: hmacHeaders(now, "", signHMAC(now, "", `{"subject":"someone"}`, secret)),
			want:    http.StatusUnauthorized,
		},
		{
			name:    "service header not covered by the signature",
			headers: hmacHeaders(now, "herald", signHMAC(now, "", authTestBody, secret)),
			want:    http.StatusUnauthorized,
		},
		{
			name: "stale timestamp outside the drift window",
			headers: hmacHeaders(
				strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10),
				"",
				signHMAC(strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10), "", authTestBody, secret),
			),
			want: http.StatusUnauthorized,
		},
		{
			name:    "no HMAC headers at all",
			headers: nil,
			want:    http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := postRevoke(t, app, tt.headers); got != tt.want {
				t.Errorf("POST /v1/revoke status = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSetup_AuthAPIKey(t *testing.T) {
	const apiKey = "api-key-test-value"
	app := newAuthTestApp(t, apiKey, "")

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{
			name:    "correct key",
			headers: map[string]string{"X-API-Key": apiKey},
			want:    http.StatusBadRequest,
		},
		{
			name:    "wrong key",
			headers: map[string]string{"X-API-Key": "wrong-key"},
			want:    http.StatusUnauthorized,
		},
		{
			name:    "empty key",
			headers: map[string]string{"X-API-Key": ""},
			want:    http.StatusUnauthorized,
		},
		{
			name:    "no key header",
			headers: nil,
			want:    http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := postRevoke(t, app, tt.headers); got != tt.want {
				t.Errorf("POST /v1/revoke status = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestSetup_AuthSchemeFallthrough covers the ordering CombinedAuth applies
// when more than one scheme is configured: mTLS is unconfigured, HMAC declines
// a request carrying no signature headers, and the API key still admits it.
func TestSetup_AuthSchemeFallthrough(t *testing.T) {
	const (
		apiKey = "both-schemes-api-key"
		secret = "both-schemes-hmac-secret"
	)
	app := newAuthTestApp(t, apiKey, secret)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{
			name:    "api key only",
			headers: map[string]string{"X-API-Key": apiKey},
			want:    http.StatusBadRequest,
		},
		{
			name:    "hmac only",
			headers: hmacHeaders(now, "", signHMAC(now, "", authTestBody, secret)),
			want:    http.StatusBadRequest,
		},
		{
			name:    "bad hmac but good api key",
			headers: map[string]string{"X-API-Key": apiKey, "X-Timestamp": now, "X-Signature": "deadbeef"},
			want:    http.StatusBadRequest,
		},
		{
			name:    "both bad",
			headers: map[string]string{"X-API-Key": "wrong", "X-Timestamp": now, "X-Signature": "deadbeef"},
			want:    http.StatusUnauthorized,
		},
		{
			name:    "no credentials",
			headers: nil,
			want:    http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := postRevoke(t, app, tt.headers); got != tt.want {
				t.Errorf("POST /v1/revoke status = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestSetup_AuthAllowNoAuth pins what the AllowNoAuth switch actually does in
// this service.
//
// config.AllowNoAuth() reports true when neither an API key nor an HMAC secret
// is configured, and Setup passes that through to CombinedAuth -- but it never
// takes effect. CombinedAuth consults AllowNoAuth only when NO scheme is
// configured, and Setup always hands it an HMACConfig whose KeyProvider is
// config.GetHMACSecret: a non-nil func value, so the HMAC scheme always counts
// as configured and an unauthenticated request is refused either way.
//
// middleware-kit v3 does not change this. v2 gated on the same
// "HMACConfig != nil && (Secret != \"\" || KeyProvider != nil)" expression, and
// this test answers 401 on both. It is pinned here so that a future change on
// either side surfaces as a failure rather than as a service that quietly
// begins admitting unauthenticated requests.
func TestSetup_AuthAllowNoAuth(t *testing.T) {
	t.Run("config reports it enabled with no credentials configured", func(t *testing.T) {
		oldAPIKey, oldHMAC := config.APIKey, config.HMACSecret
		config.APIKey, config.HMACSecret = "", ""
		defer func() { config.APIKey, config.HMACSecret = oldAPIKey, oldHMAC }()

		if !config.AllowNoAuth() {
			t.Error("config.AllowNoAuth() = false with no credentials configured, want true")
		}
	})

	t.Run("config reports it disabled with credentials configured", func(t *testing.T) {
		oldAPIKey, oldHMAC := config.APIKey, config.HMACSecret
		defer func() { config.APIKey, config.HMACSecret = oldAPIKey, oldHMAC }()

		config.APIKey, config.HMACSecret = "some-api-key", ""
		if config.AllowNoAuth() {
			t.Error("config.AllowNoAuth() = true with an API key configured, want false")
		}

		config.APIKey, config.HMACSecret = "", "some-hmac-secret"
		if config.AllowNoAuth() {
			t.Error("config.AllowNoAuth() = true with an HMAC secret configured, want false")
		}
	})

	// The middleware refuses an unauthenticated request in all three cases:
	// the always-present KeyProvider keeps the HMAC scheme configured, so the
	// AllowNoAuth branch is never reached.
	tests := []struct {
		name       string
		apiKey     string
		hmacSecret string
	}{
		{name: "no credentials configured", apiKey: "", hmacSecret: ""},
		{name: "api key configured", apiKey: "some-api-key", hmacSecret: ""},
		{name: "hmac secret configured", apiKey: "", hmacSecret: "some-hmac-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newAuthTestApp(t, tt.apiKey, tt.hmacSecret)
			if got := postRevoke(t, app, nil); got != http.StatusUnauthorized {
				t.Errorf("unauthenticated request status = %d, want 401", got)
			}
		})
	}
}
