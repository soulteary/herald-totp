package requestauth

import (
	"encoding/json"
	"github.com/soulteary/herald-totp/v2/internal/config"
	"github.com/soulteary/herald-totp/v2/pkg/heraldtotp"
	"strings"
	"testing"
)

func TestAuthenticatedIdentifierByteBoundaries(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 128), strings.Repeat("é", 64), strings.Repeat("x", 129), strings.Repeat("é", 64) + "x"} {
		for _, serviceField := range []bool{false, true} {
			calls := 0
			cfg := configFor(&calls)
			cfg.KeyProvider = func(string) string { return testSecret }
			req := signedRequest("POST", "/v1/verify", `{}`)
			service, keyID := "caller", value
			if serviceField {
				service, keyID = value, "primary"
			}
			req.Header.Set("X-Service", service)
			req.Header.Set("X-Key-Id", keyID)
			req.Header.Set("X-Signature", heraldtotp.SignV2(testSecret, heraldtotp.RequestSignature{Method: req.Method, Path: req.URL.EscapedPath(), KeyID: keyID, Timestamp: req.Header.Get("X-Timestamp"), Service: service, Nonce: req.Header.Get("X-Nonce"), Body: []byte(`{}`)}))
			status := responseStatus(t, appFor(cfg), req)
			if len(value) <= heraldtotp.MaxAuthIdentifierBytes {
				if status != 204 || calls != 1 {
					t.Fatalf("128-byte value: status=%d nonce calls=%d", status, calls)
				}
			} else if status != 401 || calls != 0 {
				t.Fatalf("129-byte value: status=%d nonce calls=%d", status, calls)
			}
		}
	}
}

func TestMappedKeySelectionRetainsOmittedIDCompatibility(t *testing.T) {
	oldKeys, oldEncryption := config.HMACKeysJSON, config.EncryptionKey
	defer func() { config.HMACKeysJSON, config.EncryptionKey = oldKeys, oldEncryption; _ = config.Initialize(nil) }()
	keyID := strings.Repeat("k", heraldtotp.MaxAuthIdentifierBytes)
	for _, multiple := range []bool{false, true} {
		keys := map[string]string{keyID: testSecret}
		if multiple {
			keys["secondary"] = "other-secret"
		}
		encoded, err := json.Marshal(keys)
		if err != nil {
			t.Fatal(err)
		}
		config.HMACKeysJSON = string(encoded)
		config.EncryptionKey = strings.Repeat("e", 32)
		if err := config.Initialize(nil); err != nil {
			t.Fatal(err)
		}
		for _, sentID := range []string{keyID, ""} {
			calls := 0
			cfg := configFor(&calls)
			cfg.KeyProvider = config.GetHMACSecret
			req := signedRequest("POST", "/v1/verify", `{}`)
			req.Header.Del("X-Key-Id")
			if sentID != "" {
				req.Header.Set("X-Key-Id", sentID)
			}
			req.Header.Set("X-Signature", heraldtotp.SignV2(testSecret, heraldtotp.RequestSignature{Method: req.Method, Path: req.URL.EscapedPath(), KeyID: sentID, Timestamp: req.Header.Get("X-Timestamp"), Service: req.Header.Get("X-Service"), Nonce: req.Header.Get("X-Nonce"), Body: []byte(`{}`)}))
			want, nonceCalls := 204, 1
			if multiple && sentID == "" {
				want, nonceCalls = 401, 0
			}
			if got := responseStatus(t, appFor(cfg), req); got != want || calls != nonceCalls {
				t.Fatalf("multiple=%t omitted=%t status=%d nonce calls=%d", multiple, sentID == "", got, calls)
			}
		}
	}
}
