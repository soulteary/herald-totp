package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v3"
	pqtotp "github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	logger "github.com/soulteary/logger-kit/v2"

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
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
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

func TestEnrollStart_GenerateError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey, oldIssuer := config.EncryptionKey, config.TOTPIssuer
	oldSubjectLimit, oldIPLimit := config.RateLimitPerSubject, config.RateLimitPerIP
	config.EncryptionKey, config.TOTPIssuer = testEncryptionKey, ""
	config.RateLimitPerSubject, config.RateLimitPerIP = 100, 100
	defer func() {
		config.EncryptionKey, config.TOTPIssuer = oldKey, oldIssuer
		config.RateLimitPerSubject, config.RateLimitPerIP = oldSubjectLimit, oldIPLimit
	}()

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/start", bytes.NewBufferString(`{"subject":"generate-error"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
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

func TestEnrollStart_ExposeSecretInEnrollFalse(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	oldExpose := config.ExposeSecretInEnroll
	config.EncryptionKey = testEncryptionKey
	config.ExposeSecretInEnroll = false
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() {
		config.EncryptionKey = oldKey
		config.ExposeSecretInEnroll = oldExpose
		config.RateLimitPerSubject = 20
		config.RateLimitPerIP = 30
	}()

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	body := `{"subject":"nosecret","label":"u"}`
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
	if out.SecretBase32 != "" {
		t.Errorf("ExposeSecretInEnroll=false: SecretBase32 should be empty, got %q", out.SecretBase32)
	}
	if out.OtpauthURI == "" || out.EnrollID == "" {
		t.Errorf("OtpauthURI and EnrollID should be set: EnrollID=%q OtpauthURI=%q", out.EnrollID, out.OtpauthURI)
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

	// The temporary enrollment is consumed by the same transaction that saves
	// the credential and backup codes.
	req = httptest.NewRequest("POST", "/enroll/confirm", bytes.NewReader(confirmBody))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("second enroll confirm status = %d, want 400", resp.StatusCode)
	}
}

func TestEnrollStart_RedisError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = oldKey }()
	mr.SetError("ERR injected failure")

	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/start", bytes.NewReader([]byte(`{"subject":"redis-error"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
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
	const challengeID = "c_verify_success"
	verifyBody, _ := json.Marshal(VerifyRequest{Subject: "vuser", Code: code2, ChallengeID: challengeID})
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
	if vOut.Subject != "vuser" {
		t.Errorf("VerifyResponse.Subject = %q, want vuser", vOut.Subject)
	}
	if len(vOut.AMR) == 0 || vOut.AMR[0] != "totp" {
		t.Errorf("VerifyResponse.AMR = %v, want [totp]", vOut.AMR)
	}
	if vOut.IssuedAt <= 0 {
		t.Errorf("VerifyResponse.IssuedAt = %d, want > 0", vOut.IssuedAt)
	}
	used, err := st.IsChallengeUsed(context.Background(), challengeID)
	if err != nil || !used {
		t.Errorf("challenge used = (%v, %v), want (true, nil)", used, err)
	}
}

func TestVerify_FutureWindowCodeCannotBeReused(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	oldSubjectLimit := config.RateLimitPerSubject
	oldIPLimit := config.RateLimitPerIP
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() {
		config.EncryptionKey = oldKey
		config.RateLimitPerSubject = oldSubjectLimit
		config.RateLimitPerIP = oldIPLimit
	}()

	cfg := totp.DefaultConfig("Herald")
	secretBase32, _, err := totp.Generate("future-user", cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	keyBytes, _ := secret.KeyBytes(testEncryptionKey)
	secretEnc, _ := secret.Encrypt(keyBytes, secretBase32)
	cred := &store.Credential{
		Subject: "future-user", SecretEnc: secretEnc, Issuer: "Herald", Label: "future-user",
		Period: 30, Digits: 6, Algo: "SHA1", Enabled: true,
	}
	if err := st.SaveCredential(context.Background(), cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	futureCode, err := pqtotp.GenerateCodeCustom(secretBase32, time.Now().Add(30*time.Second), pqtotp.ValidateOpts{
		Period: 30, Skew: 1, Digits: totp.DigitsFromInt(6), Algorithm: totp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}

	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	body, _ := json.Marshal(VerifyRequest{Subject: "future-user", Code: futureCode})
	for attempt, wantStatus := range []int{http.StatusOK, http.StatusBadRequest} {
		req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("attempt %d: app.Test: %v", attempt+1, err)
		}
		if resp.StatusCode != wantStatus {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, resp.StatusCode, wantStatus)
		}
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

func TestVerify_BackupCodeSuccess(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	config.EncryptionKey = testEncryptionKey
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.EncryptionKey = "" }()
	app := fiber.New()
	app.Post("/enroll/start", EnrollStart(st, log))
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	app.Post("/verify", Verify(st, log))
	// Enroll user to get backup codes
	req := httptest.NewRequest("POST", "/enroll/start", bytes.NewReader([]byte(`{"subject":"backupuser","label":"bu"}`)))
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
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("enroll confirm = %d", resp.StatusCode)
	}
	var confirmOut EnrollConfirmResponse
	_ = json.NewDecoder(resp.Body).Decode(&confirmOut)
	if len(confirmOut.BackupCodes) == 0 {
		t.Fatal("no backup codes returned")
	}
	backupCode := confirmOut.BackupCodes[0]
	verifyBody, _ := json.Marshal(VerifyRequest{Subject: "backupuser", Code: backupCode})
	req = httptest.NewRequest("POST", "/verify", bytes.NewReader(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("verify with backup code status = %d, want 200", resp.StatusCode)
	}
	var vOut VerifyResponse
	_ = json.NewDecoder(resp.Body).Decode(&vOut)
	if !vOut.OK || vOut.Subject != "backupuser" {
		t.Errorf("VerifyResponse = %+v", vOut)
	}
}

func TestRevoke_BadRequest(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	app := fiber.New()
	app.Post("/revoke", Revoke(st))
	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 400 {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRevoke_MalformedRequest(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	app := fiber.New()
	app.Post("/revoke", Revoke(st))
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRevoke_Success(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	ctx := context.Background()
	config.RateLimitPerSubject = 100
	config.RateLimitPerIP = 100
	defer func() { config.RateLimitPerSubject = 20; config.RateLimitPerIP = 30 }()
	cred := &store.Credential{Subject: "revuser", SecretEnc: "enc", Issuer: "Herald", Label: "revuser", Period: 30, Digits: 6, Algo: "SHA1", Enabled: true, CreatedAt: 1, UpdatedAt: 1}
	_ = st.SaveCredential(ctx, cred)
	entries := []store.BackupCodeEntry{{CodeHash: "h1", UsedAt: 0}}
	_ = st.SaveBackupCodes(ctx, "revuser", entries)
	app := fiber.New()
	app.Post("/revoke", Revoke(st))
	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader([]byte(`{"subject":"revuser"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var out RevokeResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !out.OK || out.Subject != "revuser" {
		t.Errorf("RevokeResponse = %+v", out)
	}
	credGot, _ := st.GetCredential(ctx, "revuser")
	if credGot != nil {
		t.Error("credential should be deleted after revoke")
	}
	codesGot, _ := st.GetBackupCodes(ctx, "revuser")
	if codesGot != nil {
		t.Error("backup codes should be deleted after revoke")
	}
}

func TestRevoke_RateLimited(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	config.RateLimitPerSubject = 0
	config.RateLimitPerIP = 100
	defer func() { config.RateLimitPerSubject = 20; config.RateLimitPerIP = 30 }()
	app := fiber.New()
	app.Post("/revoke", Revoke(st))
	req := httptest.NewRequest("POST", "/revoke", bytes.NewReader([]byte(`{"subject":"rateuser"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 429 {
		t.Errorf("revoke rate limited status = %d, want 429", resp.StatusCode)
	}
}

func TestRevoke_RedisError(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	mr.SetError("ERR injected failure")
	app := fiber.New()
	app.Post("/revoke", Revoke(st))
	req := httptest.NewRequest(http.MethodPost, "/revoke", bytes.NewReader([]byte(`{"subject":"redis-error"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestEnrollConfirm_MalformedRequest(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))

	req := httptest.NewRequest(http.MethodPost, "/enroll/confirm", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestEnrollConfirm_ConfigError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = ""
	defer func() { config.EncryptionKey = oldKey }()

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/confirm", bytes.NewBufferString(`{"enroll_id":"e_config","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestEnrollConfirm_RedisError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = oldKey }()
	mr.SetError("ERR injected failure")

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/confirm", bytes.NewBufferString(`{"enroll_id":"e_redis","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestEnrollConfirm_DecryptError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = oldKey }()
	if err := st.SaveEnrollment(context.Background(), &store.Enrollment{
		EnrollID: "e_bad_secret", Subject: "user", SecretEnc: "not-ciphertext", Period: 30, Digits: 6,
	}); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/confirm", bytes.NewBufferString(`{"enroll_id":"e_bad_secret","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestEnrollConfirm_InvalidCode(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	defer func() { config.EncryptionKey = oldKey }()
	secretBase32, _, err := totp.Generate("confirm-invalid", totp.DefaultConfig("Herald"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	keyBytes, err := secret.KeyBytes(testEncryptionKey)
	if err != nil {
		t.Fatalf("KeyBytes: %v", err)
	}
	secretEnc, err := secret.Encrypt(keyBytes, secretBase32)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := st.SaveEnrollment(context.Background(), &store.Enrollment{
		EnrollID: "e_invalid_code", Subject: "user", SecretEnc: secretEnc, Period: 30, Digits: 6,
	}); err != nil {
		t.Fatalf("SaveEnrollment: %v", err)
	}

	app := fiber.New()
	app.Post("/enroll/confirm", EnrollConfirm(st, log))
	req := httptest.NewRequest(http.MethodPost, "/enroll/confirm", bytes.NewBufferString(`{"enroll_id":"e_invalid_code","code":"not-a-code"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestStatus_RedisError(t *testing.T) {
	st, mr, _ := setupHandlerTest(t)
	defer mr.Close()
	mr.SetError("ERR injected failure")
	app := fiber.New()
	app.Get("/status", Status(st))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/status?subject=user", nil), fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestVerify_ErrorBranches(t *testing.T) {
	tests := []struct {
		name string
		body string
		seed func(*testing.T, *store.Store, *miniredis.Miniredis)
	}{
		{name: "malformed request", body: "{"},
		{name: "challenge lookup", body: `{"subject":"user","code":"123456","challenge_id":"c_error"}`, seed: func(_ *testing.T, _ *store.Store, mr *miniredis.Miniredis) {
			mr.SetError("ERR injected failure")
		}},
		{name: "rate limit", body: `{"subject":"user","code":"123456"}`, seed: func(_ *testing.T, _ *store.Store, mr *miniredis.Miniredis) {
			mr.SetError("ERR injected failure")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, mr, log := setupHandlerTest(t)
			defer mr.Close()
			if tt.seed != nil {
				tt.seed(t, st, mr)
			}
			app := fiber.New()
			app.Post("/verify", Verify(st, log))
			req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			want := http.StatusInternalServerError
			if tt.name == "malformed request" {
				want = http.StatusBadRequest
			}
			if resp.StatusCode != want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, want)
			}
		})
	}
}

func TestVerify_DecryptError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey, oldSubjectLimit, oldIPLimit := config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP
	config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = testEncryptionKey, 100, 100
	defer func() {
		config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = oldKey, oldSubjectLimit, oldIPLimit
	}()
	if err := st.SaveCredential(context.Background(), &store.Credential{
		Subject: "decrypt-error", SecretEnc: "not-ciphertext", Period: 30, Digits: 6, Enabled: true,
	}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(`{"subject":"decrypt-error","code":"123456"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestVerify_BackupCodeStoreError(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey, oldSubjectLimit, oldIPLimit := config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP
	config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = testEncryptionKey, 100, 100
	defer func() {
		config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = oldKey, oldSubjectLimit, oldIPLimit
	}()
	secretBase32, _, err := totp.Generate("backup-error", totp.DefaultConfig("Herald"))
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	keyBytes, _ := secret.KeyBytes(testEncryptionKey)
	secretEnc, _ := secret.Encrypt(keyBytes, secretBase32)
	if err := st.SaveCredential(context.Background(), &store.Credential{
		Subject: "backup-error", SecretEnc: secretEnc, Period: 30, Digits: 6, Enabled: true,
	}); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	if err := mr.Set("totp:backup:backup-error", "not-json"); err != nil {
		t.Fatalf("seed invalid backup codes: %v", err)
	}

	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(`{"subject":"backup-error","code":"not-a-code"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}

func TestIPRateLimit(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		bind func(*fiber.App, *store.Store, *logger.Logger)
	}{
		{name: "enroll start", path: "/enroll/start", body: `{"subject":"ip-limited"}`, bind: func(app *fiber.App, st *store.Store, log *logger.Logger) {
			app.Post("/enroll/start", EnrollStart(st, log))
		}},
		{name: "verify", path: "/verify", body: `{"subject":"ip-limited","code":"123456"}`, bind: func(app *fiber.App, st *store.Store, log *logger.Logger) {
			app.Post("/verify", Verify(st, log))
		}},
		{name: "revoke", path: "/revoke", body: `{"subject":"ip-limited"}`, bind: func(app *fiber.App, st *store.Store, _ *logger.Logger) {
			app.Post("/revoke", Revoke(st))
		}},
	}

	oldKey, oldSubjectLimit, oldIPLimit := config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP
	config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = testEncryptionKey, 100, 0
	defer func() {
		config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = oldKey, oldSubjectLimit, oldIPLimit
	}()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, mr, log := setupHandlerTest(t)
			defer mr.Close()
			app := fiber.New()
			tt.bind(app, st, log)
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", resp.StatusCode)
			}
		})
	}
}
