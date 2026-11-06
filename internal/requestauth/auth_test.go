package requestauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/soulteary/herald-totp/v2/pkg/heraldtotp"
)

const testSecret = "local-test-secret"

var testNow = time.Unix(1700000000, 0)

func signedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ts := strconv.FormatInt(testNow.Unix(), 10)
	nonce := strings.Repeat("1", 32)
	req.Header.Set("X-Signature-Version", "v2")
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Service", "caller")
	req.Header.Set("X-Key-Id", "primary")
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", heraldtotp.SignV2(testSecret, heraldtotp.RequestSignature{Method: method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, KeyID: "primary", Timestamp: ts, Service: "caller", Nonce: nonce, Body: []byte(body)}))
	return req
}
func appFor(cfg Config) *fiber.App {
	app := fiber.New()
	app.Use(New(cfg))
	app.All("/*", func(c fiber.Ctx) error { return c.SendStatus(204) })
	return app
}
func responseStatus(t *testing.T, app *fiber.App, req *http.Request) int {
	t.Helper()
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	return resp.StatusCode
}
func configFor(calls *int) Config {
	return Config{KeyProvider: func(key string) string {
		if key == "primary" {
			return testSecret
		}
		return ""
	}, Consume: func(_ context.Context, key string, ttl time.Duration) (bool, error) {
		*calls++
		if !strings.HasPrefix(key, "totp:auth:nonce:") || ttl < 2*maxDrift {
			panic("invalid replay key/retention")
		}
		return true, nil
	}, Clock: func() time.Time { return testNow }}
}
func TestHMACRejectsMalformedAndTamperedRequestsWithoutNonceMutation(t *testing.T) {
	calls := 0
	cfg := configFor(&calls)
	cfg.APIKey = "api-key"
	for name, change := range map[string]func(*http.Request){
		"legacy": func(r *http.Request) { r.Header.Del("X-Signature-Version") }, "signature": func(r *http.Request) { r.Header.Set("X-Signature", strings.Repeat("0", 64)) }, "short signature": func(r *http.Request) { r.Header.Set("X-Signature", "bad") }, "nonce length": func(r *http.Request) { r.Header.Set("X-Nonce", "bad") }, "nonce encoding": func(r *http.Request) { r.Header.Set("X-Nonce", strings.Repeat("z", 32)) }, "missing service": func(r *http.Request) { r.Header.Del("X-Service") }, "long service": func(r *http.Request) { r.Header.Set("X-Service", strings.Repeat("s", 129)) }, "long key": func(r *http.Request) { r.Header.Set("X-Key-Id", strings.Repeat("k", 129)) }, "unknown key": func(r *http.Request) { r.Header.Set("X-Key-Id", "unknown") }, "timestamp encoding": func(r *http.Request) { r.Header.Set("X-Timestamp", "bad") }, "timestamp length": func(r *http.Request) { r.Header.Set("X-Timestamp", strings.Repeat("1", 21)) }, "old": func(r *http.Request) { r.Header.Set("X-Timestamp", strconv.FormatInt(testNow.Unix()-61, 10)) }, "future": func(r *http.Request) { r.Header.Set("X-Timestamp", strconv.FormatInt(testNow.Unix()+61, 10)) }, "path": func(r *http.Request) { r.URL.Path = "/v1/revoke" }, "query": func(r *http.Request) { r.URL.RawQuery = "subject=other" }, "method": func(r *http.Request) { r.Method = "GET" }, "body": func(r *http.Request) {
			r.Body = io.NopCloser(bytes.NewBufferString(`{"other":true}`))
			r.ContentLength = int64(len(`{"other":true}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := signedRequest("POST", "/v1/verify?subject=user", `{}`)
			req.Header.Set("X-API-Key", "api-key")
			change(req)
			if got := responseStatus(t, appFor(cfg), req); got != 401 {
				t.Fatalf("status=%d", got)
			}
		})
	}
	if calls != 0 {
		t.Fatal("invalid request mutated replay store")
	}
	for _, change := range []func(*Config){func(c *Config) { c.KeyProvider = nil }, func(c *Config) { c.Consume = nil }} {
		copy := cfg
		change(&copy)
		if responseStatus(t, appFor(copy), signedRequest("POST", "/x", `{}`)) != 401 {
			t.Fatal("missing dependency accepted")
		}
	}
}
func TestHMACReplayAndBackendFailures(t *testing.T) {
	calls := 0
	cfg := configFor(&calls)
	app := appFor(cfg)
	if responseStatus(t, app, signedRequest("POST", "/x", `{}`)) != 204 || calls != 1 {
		t.Fatal("valid request rejected")
	}
	cfg.Consume = func(context.Context, string, time.Duration) (bool, error) { return false, nil }
	if responseStatus(t, appFor(cfg), signedRequest("POST", "/x", `{}`)) != 401 {
		t.Fatal("replay accepted")
	}
	cfg.Consume = func(context.Context, string, time.Duration) (bool, error) { return false, errors.New("backend down") }
	if responseStatus(t, appFor(cfg), signedRequest("POST", "/x", `{}`)) != 503 {
		t.Fatal("backend failure opened auth")
	}
	cfg.Clock = nil
	req := signedRequest("POST", "/x", `{}`)
	if responseStatus(t, appFor(cfg), req) != 401 {
		t.Fatal("stale request accepted")
	}
}
func TestAPIKeyAuthenticationIsIndependent(t *testing.T) {
	cfg := Config{APIKey: "api-key"}
	for _, tc := range []struct {
		header, value string
		want          int
	}{{"X-API-Key", "api-key", 204}, {"Authorization", "Bearer api-key", 204}, {"Authorization", "api-key", 401}, {"X-API-Key", "wrong", 401}, {"", "", 401}} {
		req := httptest.NewRequest("GET", "/x", nil)
		if tc.header != "" {
			req.Header.Set(tc.header, tc.value)
		}
		if responseStatus(t, appFor(cfg), req) != tc.want {
			t.Fatal("API key contract changed")
		}
	}
	if responseStatus(t, appFor(Config{}), httptest.NewRequest("GET", "/x", nil)) != 401 {
		t.Fatal("unconfigured auth accepted")
	}
}

func TestNonceIdentitySurvivesRequestAndKeyAliasChanges(t *testing.T) {
	calls := 0
	cfg := configFor(&calls)
	cfg.KeyProvider = func(string) string { return testSecret }
	seen := map[string]bool{}
	cfg.Consume = func(_ context.Context, key string, _ time.Duration) (bool, error) {
		if seen[key] {
			return false, nil
		}
		seen[key] = true
		return true, nil
	}
	app := appFor(cfg)
	if responseStatus(t, app, signedRequest("POST", "/x", `{}`)) != 204 {
		t.Fatal("initial request rejected")
	}
	req := signedRequest("POST", "/other", `{"different":true}`)
	if responseStatus(t, app, req) != 401 {
		t.Fatal("nonce reused across request bodies")
	}
	req = signedRequest("POST", "/x", `{}`)
	req.Header.Set("X-Key-Id", "alias")
	req.Header.Set("X-Signature", heraldtotp.SignV2(testSecret, heraldtotp.RequestSignature{Method: "POST", Path: "/x", KeyID: "alias", Timestamp: req.Header.Get("X-Timestamp"), Service: "caller", Nonce: req.Header.Get("X-Nonce"), Body: []byte(`{}`)}))
	if responseStatus(t, app, req) != 401 {
		t.Fatal("key alias bypassed nonce consumption")
	}
}
