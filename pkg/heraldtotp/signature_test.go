package heraldtotp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type brokenNonceReader struct{}

func (brokenNonceReader) Read([]byte) (int, error) { return 0, errors.New("random source unavailable") }
func TestSignRequestBindsEveryRequestField(t *testing.T) {
	req := httptest.NewRequest("POST", "https://totp.example/v1/verify?a=b", nil)
	body := []byte(`{"subject":"test-user"}`)
	now := time.Unix(1700000000, 0)
	if err := signRequest(req, body, "secret", "caller", "primary", strings.NewReader(strings.Repeat("x", 16)), now); err != nil {
		t.Fatal(err)
	}
	in := RequestSignature{Method: req.Method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, KeyID: "primary", Timestamp: req.Header.Get("X-Timestamp"), Service: "caller", Nonce: req.Header.Get("X-Nonce"), Body: body}
	original := req.Header.Get("X-Signature")
	if original != SignV2("secret", in) || req.Header.Get("X-Signature-Version") != SignatureVersion {
		t.Fatal("signature mismatch")
	}
	for _, change := range []func(*RequestSignature){func(x *RequestSignature) { x.Method = "GET" }, func(x *RequestSignature) { x.Path = "/v1/revoke" }, func(x *RequestSignature) { x.Query = "a=c" }, func(x *RequestSignature) { x.KeyID = "secondary" }, func(x *RequestSignature) { x.Timestamp = "1" }, func(x *RequestSignature) { x.Service = "other" }, func(x *RequestSignature) { x.Nonce = "other" }, func(x *RequestSignature) { x.Body = []byte(`{}`) }} {
		changed := in
		change(&changed)
		if original == SignV2("secret", changed) {
			t.Fatal("field not bound")
		}
	}
	if original == SignV2("other-secret", in) {
		t.Fatal("key not bound")
	}
	req.Header = nil
	if err := signRequest(req, nil, "secret", "caller", "", strings.NewReader(strings.Repeat("x", 16)), now); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Key-Id") != "" {
		t.Fatal("stale key ID")
	}
	if err := SignRequest(req, nil, "secret", "caller", ""); err != nil {
		t.Fatal(err)
	}
	first := req.Header.Get("X-Nonce")
	if err := SignRequest(req, nil, "secret", "caller", ""); err != nil {
		t.Fatal(err)
	}
	if first == req.Header.Get("X-Nonce") {
		t.Fatal("nonce reused")
	}
}
func TestSignRequestFailures(t *testing.T) {
	req := httptest.NewRequest("GET", "https://totp.example/", nil)
	for _, test := range []struct {
		req             *http.Request
		secret, service string
		reader          io.Reader
	}{
		{nil, "secret", "caller", strings.NewReader("")}, {&http.Request{}, "secret", "caller", strings.NewReader("")}, {req, "", "caller", strings.NewReader("")}, {req, "secret", "", strings.NewReader("")}, {req, "secret", "caller", brokenNonceReader{}},
	} {
		if err := signRequest(test.req, nil, test.secret, test.service, "", test.reader, time.Now()); err == nil {
			t.Fatal("expected signing error")
		}
	}
}
func TestClientSigningFailureDoesNotSend(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	c, err := NewClient(&Options{BaseURL: server.URL, HMACSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []func() error{
		func() error { _, e := c.Status(context.Background(), "user"); return e },
		func() error {
			_, e := c.Verify(context.Background(), &VerifyRequest{Subject: "user", Code: "123456"})
			return e
		},
		func() error {
			_, e := c.EnrollStart(context.Background(), &EnrollStartRequest{Subject: "user"})
			return e
		},
		func() error {
			_, e := c.EnrollConfirm(context.Background(), &EnrollConfirmRequest{EnrollID: "id", Code: "123456"})
			return e
		},
		func() error { _, e := c.Revoke(context.Background(), "user"); return e },
	} {
		if e := call(); e == nil {
			t.Fatal("expected signing error")
		}
	}
	if calls != 0 {
		t.Fatal("unsigned request sent")
	}
}
