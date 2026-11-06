package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2/server"
	"github.com/gofiber/fiber/v3"
	pqtotp "github.com/pquerna/otp/totp"
	"github.com/soulteary/herald-totp/v2/internal/config"
	"github.com/soulteary/herald-totp/v2/internal/secret"
	"github.com/soulteary/herald-totp/v2/internal/store"
)

func TestEnrollConfirmRateLimitsBeforeCredentialMutation(t *testing.T) {
	for _, scenario := range []string{"subject exhausted", "wrong code", "success", "IP backend failure", "subject backend failure", "enrollment backend failure"} {
		t.Run(scenario, func(t *testing.T) {
			st, mr, log := setupHandlerTest(t)
			defer mr.Close()
			oldKey, oldSub, oldIP := config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP
			config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = testEncryptionKey, 20, 30
			defer func() {
				config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = oldKey, oldSub, oldIP
			}()
			key, err := secret.KeyBytes(testEncryptionKey)
			if err != nil {
				t.Fatal(err)
			}
			seed := "JBSWY3DPEHPK3PXP"
			encrypted, err := secret.Encrypt(key, seed)
			if err != nil {
				t.Fatal(err)
			}
			enrollment := &store.Enrollment{EnrollID: "quota-enrollment", Subject: "quota-subject", SecretEnc: encrypted, Period: 30, Digits: 6, ExpiresAt: time.Now().Add(time.Minute).Unix()}
			if err = st.SaveEnrollment(context.Background(), enrollment); err != nil {
				t.Fatal(err)
			}
			before, _ := mr.Get("totp:enroll:" + enrollment.EnrollID)
			want := http.StatusBadRequest
			if scenario == "subject exhausted" {
				config.RateLimitPerSubject = 1
				for range 2 {
					if _, err = st.IncrRateSubject(context.Background(), enrollment.Subject); err != nil {
						t.Fatal(err)
					}
				}
				want = 429
			}
			if scenario == "success" {
				want = 200
			}
			if strings.Contains(scenario, "backend failure") {
				want = 500
				mr.Server().SetPreHook(func(peer *server.Peer, cmd string, args ...string) bool {
					fail := scenario == "enrollment backend failure" && strings.EqualFold(cmd, "GET") && len(args) > 0 && args[0] == "totp:enroll:"+enrollment.EnrollID
					prefix := "totp:rate:ip:"
					if scenario == "subject backend failure" {
						prefix = "totp:rate:subject:"
					}
					if scenario != "enrollment backend failure" && (strings.EqualFold(cmd, "EVAL") || strings.EqualFold(cmd, "EVALSHA")) && len(args) > 2 && strings.HasPrefix(args[2], prefix) {
						fail = true
					}
					if fail {
						peer.WriteError("ERR injected quota backend failure")
						return true
					}
					return false
				})
			}
			code, err := pqtotp.GenerateCode(seed, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong code" {
				code = "not-a-code"
			}
			encoded, _ := json.Marshal(EnrollConfirmRequest{EnrollID: enrollment.EnrollID, Code: code})
			app := fiber.New()
			app.Post("/confirm", EnrollConfirm(st, log))
			req := httptest.NewRequest("POST", "/confirm", strings.NewReader(string(encoded)))
			req.Header.Set("Content-Type", "application/json")
			response, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != want {
				t.Fatalf("status=%d want=%d", response.StatusCode, want)
			}
			if want != 200 {
				after, _ := mr.Get("totp:enroll:" + enrollment.EnrollID)
				if after != before || mr.Exists("totp:cred:"+enrollment.Subject) || mr.Exists("totp:backup:"+enrollment.Subject) {
					t.Fatal("rejected confirmation mutated enrollment or credentials")
				}
			} else if mr.Exists("totp:enroll:"+enrollment.EnrollID) || !mr.Exists("totp:cred:"+enrollment.Subject) {
				t.Fatal("successful confirmation did not commit")
			}
			if scenario == "wrong code" || scenario == "success" {
				if count, err := mr.Get("totp:rate:subject:" + enrollment.Subject); err != nil || count != "1" {
					t.Fatalf("subject count=%q error=%v", count, err)
				}
				keys := mr.Keys()
				ipKeys := 0
				for _, key := range keys {
					if strings.HasPrefix(key, "totp:rate:ip:") {
						ipKeys++
						count, _ := mr.Get(key)
						if count != "1" {
							t.Fatalf("IP counted more than once: %s", count)
						}
					}
				}
				if ipKeys != 1 {
					t.Fatalf("IP keys=%d", ipKeys)
				}
			}
		})
	}
}

func TestEnrollConfirmUnknownIDsShareIPBudget(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey, oldIP := config.EncryptionKey, config.RateLimitPerIP
	config.EncryptionKey, config.RateLimitPerIP = testEncryptionKey, 1
	defer func() { config.EncryptionKey, config.RateLimitPerIP = oldKey, oldIP }()
	app := fiber.New()
	app.Post("/confirm", EnrollConfirm(st, log))
	for i, want := range []int{400, 429} {
		body, _ := json.Marshal(EnrollConfirmRequest{EnrollID: []string{"unknown-one", "unknown-two"}[i], Code: "123456"})
		req := httptest.NewRequest("POST", "/confirm", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("status=%d want=%d", resp.StatusCode, want)
		}
	}
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "totp:rate:subject:") {
			t.Fatal("unknown enrollment consumed arbitrary subject quota")
		}
		if strings.HasPrefix(key, "totp:rate:ip:") {
			count, _ := mr.Get(key)
			if count != "2" {
				t.Fatalf("IP count=%s", count)
			}
		}
	}
}

func TestEnrollStartAndConfirmShareSubjectBudget(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey, oldSub, oldIP := config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP
	config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = testEncryptionKey, 1, 30
	defer func() {
		config.EncryptionKey, config.RateLimitPerSubject, config.RateLimitPerIP = oldKey, oldSub, oldIP
	}()
	app := fiber.New()
	app.Post("/start", EnrollStart(st, log))
	app.Post("/confirm", EnrollConfirm(st, log))
	request := httptest.NewRequest("POST", "/start", strings.NewReader(`{"subject":"shared-budget"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	var enrollment EnrollStartResponse
	if err = json.NewDecoder(response.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 || enrollment.EnrollID == "" {
		t.Fatalf("start status=%d", response.StatusCode)
	}
	confirm := func(want int) {
		t.Helper()
		body, _ := json.Marshal(EnrollConfirmRequest{EnrollID: enrollment.EnrollID, Code: "123456"})
		req := httptest.NewRequest("POST", "/confirm", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("confirm status=%d want=%d", resp.StatusCode, want)
		}
	}
	confirm(429)
	if !mr.Exists("totp:enroll:"+enrollment.EnrollID) || mr.Exists("totp:cred:shared-budget") {
		t.Fatal("quota denial changed enrollment")
	}
	mr.FastForward(time.Hour)
	confirm(400)
	if mr.Exists("totp:enroll:"+enrollment.EnrollID) || mr.Exists("totp:cred:shared-budget") {
		t.Fatal("expired enrollment was revived")
	}
}
