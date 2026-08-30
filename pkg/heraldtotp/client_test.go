package heraldtotp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewClient_EmptyBaseURL(t *testing.T) {
	_, err := NewClient(DefaultOptions().WithBaseURL(""))
	if err == nil {
		t.Fatal("expected error when base URL is empty")
	}
}

func TestNewClient_NilOptions(t *testing.T) {
	if _, err := NewClient(nil); err == nil {
		t.Fatal("NewClient(nil) should require a base URL")
	}
}

func TestClient_RequestCreationErrors(t *testing.T) {
	client, err := NewClient(DefaultOptions().WithBaseURL("%"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tests := []struct {
		name string
		call func() error
	}{
		{name: "status", call: func() error { _, err := client.Status(context.Background(), "user"); return err }},
		{name: "enroll start", call: func() error { _, err := client.EnrollStart(context.Background(), &EnrollStartRequest{}); return err }},
		{name: "enroll confirm", call: func() error {
			_, err := client.EnrollConfirm(context.Background(), &EnrollConfirmRequest{})
			return err
		}},
		{name: "revoke", call: func() error { _, err := client.Revoke(context.Background(), "user"); return err }},
		{name: "verify", call: func() error { _, err := client.Verify(context.Background(), &VerifyRequest{}); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); err == nil {
				t.Fatal("expected request creation error")
			}
		})
	}
}

func TestClient_TransportErrors(t *testing.T) {
	errTransport := errors.New("transport failed")
	client, err := NewClient(DefaultOptions().WithBaseURL("http://example.test"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errTransport
	})
	tests := []struct {
		name string
		call func() error
	}{
		{name: "status", call: func() error { _, err := client.Status(context.Background(), "user"); return err }},
		{name: "enroll start", call: func() error { _, err := client.EnrollStart(context.Background(), &EnrollStartRequest{}); return err }},
		{name: "enroll confirm", call: func() error {
			_, err := client.EnrollConfirm(context.Background(), &EnrollConfirmRequest{})
			return err
		}},
		{name: "revoke", call: func() error { _, err := client.Revoke(context.Background(), "user"); return err }},
		{name: "verify", call: func() error { _, err := client.Verify(context.Background(), &VerifyRequest{}); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, errTransport) {
				t.Fatalf("error = %v, want transport failed", err)
			}
		})
	}
}

func TestClient_ResponseEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		call    func(*Client) error
		wantErr bool
	}{
		{name: "enroll start invalid JSON", status: http.StatusOK, body: "not-json", call: func(c *Client) error {
			_, err := c.EnrollStart(context.Background(), &EnrollStartRequest{})
			return err
		}, wantErr: true},
		{name: "enroll confirm non-OK", status: http.StatusBadRequest, body: `{}`, call: func(c *Client) error {
			_, err := c.EnrollConfirm(context.Background(), &EnrollConfirmRequest{})
			return err
		}, wantErr: true},
		{name: "revoke invalid JSON", status: http.StatusOK, body: "not-json", call: func(c *Client) error { _, err := c.Revoke(context.Background(), "user"); return err }, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			err = tt.call(client)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputeHMAC_WithBody(t *testing.T) {
	client := &Client{hmacSecret: "secret"}
	withoutBody := client.computeHMAC("1", "service", nil)
	withBody := client.computeHMAC("1", "service", []byte(`{"ok":true}`))
	if withoutBody == withBody || len(withBody) != sha256HexLength {
		t.Fatalf("unexpected HMAC values: without=%q with=%q", withoutBody, withBody)
	}
}

const sha256HexLength = 64

func TestClient_Status_Verify_Revoke(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(StatusResponse{Subject: "user1", TotpEnabled: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/verify":
			_ = json.NewEncoder(w).Encode(VerifyResponse{
				OK: true, Subject: "user1", AMR: []string{"totp"}, IssuedAt: 1700000000,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/revoke":
			_ = json.NewEncoder(w).Encode(RevokeResponse{OK: true, Subject: "user1"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL).WithAPIKey("test-key"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	// Status
	statusResp, err := client.Status(ctx, "user1")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if statusResp.Subject != "user1" || !statusResp.TotpEnabled {
		t.Errorf("Status: got subject=%q totp_enabled=%v", statusResp.Subject, statusResp.TotpEnabled)
	}

	// Verify
	verifyResp, err := client.Verify(ctx, &VerifyRequest{Subject: "user1", Code: "123456"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verifyResp.OK || verifyResp.Subject != "user1" || verifyResp.IssuedAt != 1700000000 {
		t.Fatalf("Verify: incomplete response: %+v", verifyResp)
	}
	if len(verifyResp.AMR) != 1 || verifyResp.AMR[0] != "totp" {
		t.Fatalf("Verify: AMR = %v, want [totp]", verifyResp.AMR)
	}

	// Revoke
	revokeResp, err := client.Revoke(ctx, "user1")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !revokeResp.OK || revokeResp.Subject != "user1" {
		t.Errorf("Revoke: got ok=%v subject=%q", revokeResp.OK, revokeResp.Subject)
	}
}

func TestClient_EnrollStart_EnrollConfirm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/enroll/start":
			_ = json.NewEncoder(w).Encode(EnrollStartResponse{
				EnrollID:   "e1",
				OtpauthURI: "otpauth://totp/Test:user1?secret=JBSWY3DPEHPK3PXP",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/enroll/confirm":
			_ = json.NewEncoder(w).Encode(EnrollConfirmResponse{
				Subject:     "user1",
				TotpEnabled: true,
				BackupCodes: []string{"abc", "def"},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL).WithTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	startResp, err := client.EnrollStart(ctx, &EnrollStartRequest{Subject: "user1", Label: "user1@example.com"})
	if err != nil {
		t.Fatalf("EnrollStart: %v", err)
	}
	if startResp.EnrollID != "e1" || startResp.OtpauthURI == "" {
		t.Errorf("EnrollStart: got enroll_id=%q otpauth_uri=%q", startResp.EnrollID, startResp.OtpauthURI)
	}

	confirmResp, err := client.EnrollConfirm(ctx, &EnrollConfirmRequest{EnrollID: "e1", Code: "123456"})
	if err != nil {
		t.Fatalf("EnrollConfirm: %v", err)
	}
	if confirmResp.Subject != "user1" || !confirmResp.TotpEnabled || len(confirmResp.BackupCodes) != 2 {
		t.Errorf("EnrollConfirm: got subject=%q totp_enabled=%v backup_codes=%v",
			confirmResp.Subject, confirmResp.TotpEnabled, confirmResp.BackupCodes)
	}
}

func TestClient_Status_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Status(context.Background(), "user1")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestClient_Status_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Status(context.Background(), "user1")
	if err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
}

func TestClient_Verify_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Verify(context.Background(), &VerifyRequest{Subject: "user1", Code: "123456"})
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestClient_Verify_NonJSONGatewayErrorPreservesHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>upstream unavailable</html>"))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Verify(context.Background(), &VerifyRequest{Subject: "user1", Code: "123456"})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("error = %T %v, want *HTTPError", err, err)
	}
	if httpErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", httpErr.StatusCode)
	}
	if !strings.Contains(httpErr.Body, "upstream unavailable") {
		t.Fatalf("body summary = %q, want gateway response", httpErr.Body)
	}
}

func TestClient_Verify_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Verify(context.Background(), &VerifyRequest{Subject: "user1", Code: "123456"})
	if err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
}

func TestClient_EnrollStart_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid request"}`))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.EnrollStart(context.Background(), &EnrollStartRequest{Subject: "user1", Label: "u@e.com"})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestClient_EnrollConfirm_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid`))
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.EnrollConfirm(context.Background(), &EnrollConfirmRequest{EnrollID: "e1", Code: "123456"})
	if err == nil {
		t.Fatal("expected error for invalid JSON body")
	}
}

func TestClient_Revoke_NonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := w.Write([]byte(`{"ok":false,"reason":"rate_limited"}`)); err != nil {
			return
		}
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Revoke(context.Background(), "user1")
	if err == nil {
		t.Fatal("expected error for 429 response")
	}
}

func TestClient_WithHMACSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Timestamp") == "" || r.Header.Get("X-Service") == "" || r.Header.Get("X-Signature") == "" || r.Header.Get("X-Key-Id") != "primary" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(StatusResponse{Subject: "user1", TotpEnabled: true})
	}))
	defer server.Close()

	client, err := NewClient(DefaultOptions().
		WithBaseURL(server.URL).
		WithHMACSecret("test-hmac-secret").
		WithHMACKeyID("primary").
		WithTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	statusResp, err := client.Status(context.Background(), "user1")
	if err != nil {
		t.Fatalf("Status with HMAC: %v", err)
	}
	if statusResp.Subject != "user1" || !statusResp.TotpEnabled {
		t.Errorf("Status: got subject=%q totp_enabled=%v", statusResp.Subject, statusResp.TotpEnabled)
	}
}
