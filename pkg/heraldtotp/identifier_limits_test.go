package heraldtotp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type forbiddenNonceReader struct{ t *testing.T }

func (r forbiddenNonceReader) Read([]byte) (int, error) {
	r.t.Fatal("invalid identifiers reached random source")
	return 0, nil
}

func TestSigningIdentifierByteLimits(t *testing.T) {
	for _, value := range []string{strings.Repeat("a", 128), strings.Repeat("é", 64)} {
		req := httptest.NewRequest("POST", "https://totp.example/v1/verify", nil)
		if err := SignRequest(req, nil, "secret", value, value); err != nil {
			t.Fatalf("128 bytes rejected: %v", err)
		}
	}
	for _, value := range []string{strings.Repeat("a", 129), strings.Repeat("é", 64) + "a"} {
		for _, serviceField := range []bool{false, true} {
			for _, nilHeaders := range []bool{false, true} {
				req := httptest.NewRequest("POST", "https://totp.example/v1/verify", nil)
				req.Header = http.Header{"X-Signature": {"untouched"}, "X-Key-Id": {"previous"}}
				if nilHeaders {
					req.Header = nil
				}
				before := req.Header.Clone()
				service, keyID := "caller", value
				if serviceField {
					service, keyID = value, "primary"
				}
				if err := signRequest(req, nil, "secret", service, keyID, forbiddenNonceReader{t}, time.Now()); err == nil {
					t.Fatal("oversized identifier accepted")
				}
				if !reflect.DeepEqual(before, req.Header) {
					t.Fatal("rejected signing changed headers")
				}
			}
		}
	}
}

func TestClientOversizedIdentifiersDoNotSend(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	for _, opts := range []*Options{
		{BaseURL: server.URL, HMACSecret: "secret", Service: strings.Repeat("s", 129)},
		{BaseURL: server.URL, HMACSecret: "secret", Service: "caller", HMACKeyID: strings.Repeat("k", 129)},
	} {
		c, err := NewClient(opts)
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
			if err := call(); err == nil {
				t.Fatal("expected identifier error")
			}
		}
	}
	if calls != 0 {
		t.Fatal("invalid signed request sent")
	}
}
