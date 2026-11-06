package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	pqtotp "github.com/pquerna/otp/totp"
	"github.com/soulteary/herald-totp/v2/internal/config"
	"github.com/soulteary/herald-totp/v2/internal/secret"
	"github.com/soulteary/herald-totp/v2/internal/store"
	secure "github.com/soulteary/secure-kit/v2"
)

type unavailableEntropy struct{}

func (unavailableEntropy) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBackupCodeEntropyFailurePreservesEnrollment(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	t.Cleanup(func() { config.EncryptionKey = oldKey })
	const seed = "JBSWY3DPEHPK3PXP"
	encrypted, err := secret.Encrypt([]byte(testEncryptionKey), seed)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := &store.Enrollment{EnrollID: "entropy-enrollment", Subject: "entropy-subject", SecretEnc: encrypted, Period: 30, Digits: 6}
	if err := st.SaveEnrollment(context.Background(), enrollment); err != nil {
		t.Fatal(err)
	}
	code, err := pqtotp.GenerateCode(seed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	secure.SetRandReader(unavailableEntropy{})
	t.Cleanup(func() { secure.SetRandReader(nil) })
	if codes, err := generateBackupCodes(1); err == nil || codes != nil {
		t.Fatalf("entropy failure returned codes=%v error=%v", codes, err)
	}
	app := fiber.New()
	app.Post("/confirm", EnrollConfirm(st, log))
	payload, _ := json.Marshal(EnrollConfirmRequest{EnrollID: enrollment.EnrollID, Code: code})
	req := httptest.NewRequest(http.MethodPost, "/confirm", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var out ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 500 || out.OK || out.Reason != "internal_error" {
		t.Fatalf("response=%d %+v", response.StatusCode, out)
	}
	credential, err := st.GetCredential(context.Background(), enrollment.Subject)
	if err != nil || credential != nil {
		t.Fatalf("failed generation committed credential=%+v error=%v", credential, err)
	}
	pending, err := st.GetEnrollment(context.Background(), enrollment.EnrollID)
	if err != nil || pending == nil {
		t.Fatalf("failed generation consumed enrollment=%+v error=%v", pending, err)
	}
}

func TestEnrollmentNonceFailureDoesNotPersistSecret(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	t.Cleanup(func() { config.EncryptionKey = oldKey })
	// Supply the 20-byte TOTP secret and 12-byte ID, then fail the AES-GCM nonce read.
	oldReader := rand.Reader
	rand.Reader = bytes.NewReader(make([]byte, 32))
	t.Cleanup(func() { rand.Reader = oldReader })
	app := fiber.New()
	app.Post("/start", EnrollStart(st, log))
	req := httptest.NewRequest(http.MethodPost, "/start", strings.NewReader(`{"subject":"nonce-failure"}`))
	req.Header.Set("Content-Type", "application/json")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 500 {
		t.Fatalf("nonce failure status=%d, want 500", response.StatusCode)
	}
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "totp:enroll:") || strings.HasPrefix(key, "totp:enroll_subject:") {
			t.Fatal("nonce failure persisted enrollment state")
		}
	}
}
