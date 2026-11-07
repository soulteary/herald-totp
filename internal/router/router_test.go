package router

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"github.com/soulteary/herald-totp/v2/pkg/heraldtotp"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v3"
	logger "github.com/soulteary/logger-kit/v3"

	"github.com/soulteary/herald-totp/v2/internal/config"
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
	// Without valid credentials, authentication rejects the request before body validation.
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
	// Without valid credentials, authentication rejects the request before subject validation.
	req := httptest.NewRequest("GET", "/v1/status", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/status status = %d, want 400 or 401", resp.StatusCode)
	}
}

// --- Request authentication regression coverage ---
// These tests exercise the local operation-bound HMAC and API-key middleware.

// authTestBody carries no subject, so a request that authenticates reaches the
// revoke handler and is answered 400; one that does not is answered 401. That
// difference is what every assertion here reads.
const authTestBody = `{}`

// newAuthTestApp builds the real router against miniredis with credentials
// installed before Setup constructs requestauth.New.
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

// signHMAC builds v2 headers for a specific route and unique nonce.
var authNonce atomic.Uint64

func signHMAC(timestamp, service, body, secret string) string {
	nonce := fmt.Sprintf("%032x", authNonce.Add(1))
	signature := heraldtotp.SignV2(secret, heraldtotp.RequestSignature{Method: "POST", Path: "/v1/revoke", Timestamp: timestamp, Service: service, Nonce: nonce, Body: []byte(body)})
	return nonce + ":" + signature
}
func hmacHeaders(timestamp, service, encoded string) map[string]string {
	nonce, signature, found := strings.Cut(encoded, ":")
	if !found {
		signature = encoded
		nonce = strings.Repeat("0", 32)
	}
	return map[string]string{"X-Signature-Version": "v2", "X-Nonce": nonce, "X-Timestamp": timestamp, "X-Service": service, "X-Signature": signature}
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
			headers: hmacHeaders(now, "herald", signHMAC(now, "herald", authTestBody, secret)),
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

// TestSetup_AuthSchemeFallthrough checks independent API-key authentication when
// no HMAC headers are supplied. An attempted HMAC request cannot fall back.
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
			headers: hmacHeaders(now, "herald", signHMAC(now, "herald", authTestBody, secret)),
			want:    http.StatusBadRequest,
		},
		{
			name:    "bad hmac cannot fall back to a good api key",
			headers: map[string]string{"X-API-Key": apiKey, "X-Timestamp": now, "X-Signature": "deadbeef"},
			want:    http.StatusUnauthorized,
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

// TestSetup_AuthAllowNoAuth checks the configuration helper separately from
// the router: requestauth.New always requires valid business credentials.
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
	// requestauth.New has no anonymous business-route branch.
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

func TestSetupUsesTLSAndRejectsRedisAuthenticationFailure(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer certificateServer.Close()
	caPath := filepath.Join(t.TempDir(), "redis-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	mr := miniredis.NewMiniRedis()
	if err := mr.StartTLS(&tls.Config{Certificates: certificateServer.TLS.Certificates, MinVersion: tls.VersionTLS12}); err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	oldAddr, oldPassword, oldTLS, oldCA := config.RedisAddr, config.RedisPassword, config.RedisTLSEnabled, config.RedisTLSCAFile
	t.Cleanup(func() {
		config.RedisAddr, config.RedisPassword, config.RedisTLSEnabled, config.RedisTLSCAFile = oldAddr, oldPassword, oldTLS, oldCA
	})
	config.RedisAddr, config.RedisPassword, config.RedisTLSEnabled, config.RedisTLSCAFile = mr.Addr(), "", true, caPath
	log := logger.New(logger.Config{Level: logger.Disabled})
	st, err := Setup(fiber.New(), log)
	if err != nil || st == nil {
		t.Fatalf("TLS setup store=%v error=%v", st, err)
	}
	if credential, err := st.GetCredential(context.Background(), "missing-subject"); err != nil || credential != nil {
		t.Fatalf("TLS Redis operation credential=%+v error=%v", credential, err)
	}
	mr.RequireAuth("test-redis-password")
	config.RedisPassword = "incorrect-test-password"
	if st, err := Setup(fiber.New(), log); err == nil || st != nil {
		t.Fatalf("invalid Redis authentication did not fail closed: %v %v", st, err)
	}
}
