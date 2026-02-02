package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	logger "github.com/soulteary/logger-kit"
	pqtotp "github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/secret"
	"github.com/soulteary/herald-totp/internal/store"
	"github.com/soulteary/herald-totp/internal/totp"
)

const testEncryptionKey = "0123456789abcdef0123456789abcdef" // 32 bytes

func setupHandlerTest(t *testing.T) (*store.Store, *miniredis.Miniredis, *logger.Logger) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	enrollTTL := 10 * time.Minute
	chUsedTTL := 5 * time.Minute
	rateSubTTL := time.Hour
	rateIPTTL := time.Minute
	st := store.NewStore(rdb, enrollTTL, 0, chUsedTTL, rateSubTTL, rateIPTTL)
	log := logger.New(logger.Config{Level: logger.Disabled})
	return st, mr, log
}

func TestEnrollStart_BadRequest(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))

	// invalid JSON
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}

	// missing subject
	body := `{"label":"u1"}`
	req = httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (missing subject)", resp.StatusCode)
	}
}

func TestEnrollStart_ConfigError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = "" // invalid
	defer func() { config.EncryptionKey = oldKey }()

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	body := `{"subject":"user1","label":"u1"}`
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500 (config_error)", resp.StatusCode)
	}
}

func TestEnrollStart_Success(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	oldSub := config.RateLimitPerSubject
	oldIP := config.RateLimitPerIP
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() {
		config.EncryptionKey = oldKey
		config.RateLimitPerSubject = oldSub
		config.RateLimitPerIP = oldIP
	}()

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	body := `{"subject":"user1","label":"u1"}`
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var out EnrollStartResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.EnrollID == "" || !strings.HasPrefix(out.EnrollID, "e_") {
		t.Errorf("EnrollID = %q", out.EnrollID)
	}
	if out.SecretBase32 == "" || out.OtpauthURI == "" {
		t.Errorf("SecretBase32 or OtpauthURI empty")
	}
}

func TestEnrollConfirm_BadRequest(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = "" }()

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	body := `{}`
	req := httptest.NewRequest("POST", "/enroll/confirm", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEnrollConfirm_Expired(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = "" }()

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	body := `{"enroll_id":"e_nonexistent","code":"123456"}`
	req := httptest.NewRequest("POST", "/enroll/confirm", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (expired)", resp.StatusCode)
	}
}

func TestEnrollConfirm_Success(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = oldKey }()

	// 1) Enroll start
	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(`{"subject":"user2","label":"u2"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll start status = %d", resp.StatusCode)
	}
	var startOut EnrollStartResponse
	_ = json.NewDecoder(resp.Body).Decode(&startOut)

	// 2) Generate valid TOTP code at current time
	code, err := pqtotp.GenerateCodeCustom(startOut.SecretBase32, time.Now(), pqtotp.ValidateOpts{
		Period: uint(config.TOTPPeriod), Skew: uint(config.TOTPSkew),
		Digits: totp.DigitsFromInt(config.TOTPDigits), Algorithm: totp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	// 3) Confirm
	confirmBody, _ := json.Marshal(EnrollConfirmRequest{EnrollID: startOut.EnrollID, Code: code})
	req = httptest.NewRequest("POST", "/enroll/confirm", bytes.NewReader(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("enroll confirm status = %d", resp.StatusCode)
	}
	var confirmOut EnrollConfirmResponse
	_ = json.NewDecoder(resp.Body).Decode(&confirmOut)
	if !confirmOut.TotpEnabled || confirmOut.Subject != "user2" {
		t.Errorf("confirm response = %+v", confirmOut)
	}
}

func TestVerify_BadRequest(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestVerify_NoCredential(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body := `{"subject":"nobody","code":"123456"}`
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (invalid)", resp.StatusCode)
	}
}

func TestVerify_Success(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	// Enroll user then verify with valid code
	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	app.Post("/verify", Verify(st, log))
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(`{"subject":"vuser","label":"vuser"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll start = %d", resp.StatusCode)
	}
	var startOut EnrollStartResponse
	_ = json.NewDecoder(resp.Body).Decode(&startOut)
	code, _ := pqtotp.GenerateCodeCustom(startOut.SecretBase32, time.Now(), pqtotp.ValidateOpts{
		Period: uint(config.TOTPPeriod), Skew: uint(config.TOTPSkew),
		Digits: totp.DigitsFromInt(config.TOTPDigits), Algorithm: totp.AlgorithmSHA1,
	})
	confirmBody, _ := json.Marshal(EnrollConfirmRequest{EnrollID: startOut.EnrollID, Code: code})
	req = httptest.NewRequest("POST", "/enroll/confirm", bytes.NewReader(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test enroll confirm: %v", err)
	}
	// Now verify with same code (same time step) - might fail if step advanced; use fresh code
	code2, _ := pqtotp.GenerateCodeCustom(startOut.SecretBase32, time.Now(), pqtotp.ValidateOpts{
		Period: uint(config.TOTPPeriod), Skew: uint(config.TOTPSkew),
		Digits: totp.DigitsFromInt(config.TOTPDigits), Algorithm: totp.AlgorithmSHA1,
	})
	verifyBody, _ := json.Marshal(VerifyRequest{Subject: "vuser", Code: code2})
	req = httptest.NewRequest("POST", "/verify", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("verify status = %d, want 200", resp.StatusCode)
	}
	var vOut VerifyResponse
	_ = json.NewDecoder(resp.Body).Decode(&vOut)
	if !vOut.OK {
		t.Error("VerifyResponse.OK = false")
	}
}

func TestStatus_BadRequest(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	app := fiber.New()
	app.Get("/status", Status(st))
	req := httptest.NewRequest("GET", "/status", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestStatus_Success(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	cred := &store.Credential{Subject: "s1", SecretEnc: "e", Issuer: "Herald", Label: "s1", Period: 30, Digits: 6, Algo: "SHA1", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	_ = st.SaveCredential(ctx, cred)
	app := fiber.New()
	app.Get("/status", Status(st))
	req := httptest.NewRequest("GET", "/status?subject=s1", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var out StatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Subject != "s1" || !out.TotpEnabled {
		t.Errorf("StatusResponse = %+v", out)
	}
	req = httptest.NewRequest("GET", "/status?subject=none", nil)
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("status(none) = %d", resp.StatusCode)
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.TotpEnabled {
		t.Error("subject none should not have totp_enabled")
	}
}

func TestVerify_ConfigError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	// Save credential so we pass cred check and hit config (EncryptionKey) check
	cred := &store.Credential{Subject: "any", SecretEnc: "enc", Issuer: "Herald", Label: "any", Period: 30, Digits: 6, Algo: "SHA1", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	_ = st.SaveCredential(ctx, cred)
	oldKey := config.EncryptionKey
	config.EncryptionKey = ""
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = oldKey }()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body := `{"subject":"any","code":"123456"}`
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 500 {
		t.Errorf("status = %d, want 500 (config_error)", resp.StatusCode)
	}
}

func TestVerify_ReplayChallenge(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	_ = st.MarkChallengeUsed(ctx, "c_already_used")
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body := `{"subject":"any","code":"123456","challenge_id":"c_already_used"}`
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (replay)", resp.StatusCode)
	}
}

func TestVerify_InvalidCode(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	// Create credential with real encrypted TOTP secret so Decrypt succeeds, then wrong code -> 401
	secretBase32, _, _ := totp.Generate("inv", totp.DefaultConfig("Herald"))
	keyBytes, _ := secret.KeyBytes(testEncryptionKey)
	secretEnc, _ := secret.Encrypt(keyBytes, secretBase32)
	cred := &store.Credential{Subject: "inv", SecretEnc: secretEnc, Issuer: "Herald", Label: "inv", Period: 30, Digits: 6, Algo: "SHA1", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	_ = st.SaveCredential(ctx, cred)
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body := `{"subject":"inv","code":"000000"}`
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 401 {
		t.Errorf("status = %d, want 401 (invalid)", resp.StatusCode)
	}
}

func TestVerify_DisabledCredential(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	cred := &store.Credential{Subject: "dis", SecretEnc: "enc", Issuer: "Herald", Label: "dis", Period: 30, Digits: 6, Algo: "SHA1", Enabled: false, CreatedAt: 1, UpdatedAt: 1}
	_ = st.SaveCredential(ctx, cred)
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body := `{"subject":"dis","code":"123456"}`
	req := httptest.NewRequest("POST", "/verify", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (invalid/disabled)", resp.StatusCode)
	}
}

func TestEnrollStart_RateLimited(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 0 // allow 0 per hour
	config.RateLimitPerIP = 100
	defer func() {
		config.EncryptionKey = ""
		config.RateLimitPerSubject = 20
	}()
	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	body := `{"subject":"rateuser","label":"u"}`
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 429 {
		t.Errorf("status = %d, want 429 (rate_limited)", resp.StatusCode)
	}
}
