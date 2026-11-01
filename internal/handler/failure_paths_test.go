package handler

import (
	"bytes"
	"context"
	"encoding/json"
	secure "github.com/soulteary/secure-kit/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2/server"
	"github.com/gofiber/fiber/v3"
	pqtotp "github.com/pquerna/otp/totp"
	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/secret"
	"github.com/soulteary/herald-totp/internal/store"
)

func TestEnrollmentConflictsAndCommitFailures(t *testing.T) {
	for _, scenario := range []string{"existing credential", "active enrollment", "start storage failure", "confirm conflict", "confirm expired index", "confirm storage failure"} {
		t.Run(scenario, func(t *testing.T) {
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
			enrollment := &store.Enrollment{EnrollID: "failure-enrollment", Subject: "failure-user", SecretEnc: encrypted, Period: 30, Digits: 6}
			if scenario != "existing credential" && scenario != "start storage failure" {
				if err := st.SaveEnrollment(context.Background(), enrollment); err != nil {
					t.Fatal(err)
				}
			}
			want := http.StatusConflict
			if scenario == "existing credential" || scenario == "confirm conflict" {
				if err := st.SaveCredential(context.Background(), &store.Credential{Subject: enrollment.Subject}); err != nil {
					t.Fatal(err)
				}
			}
			path := "/start"
			body := `{"subject":"failure-user"}`
			if strings.HasPrefix(scenario, "confirm") {
				path = "/confirm"
				code, err := pqtotp.GenerateCode(seed, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				encoded, _ := json.Marshal(EnrollConfirmRequest{EnrollID: enrollment.EnrollID, Code: code})
				body = string(encoded)
			}
			if scenario == "confirm expired index" {
				mr.Del("totp:enroll_subject:" + enrollment.Subject)
				want = http.StatusBadRequest
			}
			if strings.Contains(scenario, "storage failure") {
				want = http.StatusInternalServerError
				mr.Server().SetPreHook(func(peer *server.Peer, cmd string, args ...string) bool {
					if strings.EqualFold(cmd, "WATCH") || (strings.EqualFold(cmd, "EVALSHA") && len(args) > 2 && strings.HasPrefix(args[2], "totp:enroll:")) || (strings.EqualFold(cmd, "EVAL") && len(args) > 2 && strings.HasPrefix(args[2], "totp:enroll:")) {
						peer.WriteError("ERR injected persistence failure")
						return true
					}
					return false
				})
			}
			app := fiber.New()
			app.Post("/start", EnrollStart(st, log))
			app.Post("/confirm", EnrollConfirm(st, log))
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != want {
				t.Fatalf("status=%d, want %d for %s", resp.StatusCode, want, scenario)
			}
			if strings.Contains(scenario, "storage failure") {
				var out ErrorResponse
				if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
					t.Fatal(err)
				}
				if out.OK || out.Reason != "internal_error" {
					t.Fatalf("response=%+v", out)
				}
			}
		})
	}
}

func TestVerifyAndRevokeStorageFailures(t *testing.T) {
	for _, scenario := range []string{"credential read", "counter commit", "revoke commit", "IP rate counter", "backup challenge recheck"} {
		t.Run(scenario, func(t *testing.T) {
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
			if err := st.SaveCredential(context.Background(), &store.Credential{Subject: "failure-user", SecretEnc: encrypted, Enabled: true, Period: 30, Digits: 6}); err != nil {
				t.Fatal(err)
			}
			code, err := pqtotp.GenerateCode(seed, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			challenge := ""
			var challengeReads int
			if scenario == "backup challenge recheck" {
				code = "invalid-code"
				challenge = "failure-challenge"
			}
			mr.Server().SetPreHook(func(peer *server.Peer, cmd string, args ...string) bool {
				fail := scenario == "credential read" && strings.EqualFold(cmd, "GET") && len(args) > 0 && args[0] == "totp:cred:failure-user"
				if scenario == "counter commit" && strings.EqualFold(cmd, "WATCH") {
					fail = true
				}
				if scenario == "revoke commit" && (strings.EqualFold(cmd, "EVAL") || strings.EqualFold(cmd, "EVALSHA")) && len(args) > 2 && args[2] == "totp:cred:failure-user" {
					fail = true
				}
				if scenario == "IP rate counter" && (strings.EqualFold(cmd, "EVAL") || strings.EqualFold(cmd, "EVALSHA")) && len(args) > 2 && strings.HasPrefix(args[2], "totp:rate:ip:") {
					fail = true
				}
				if scenario == "backup challenge recheck" && strings.EqualFold(cmd, "EXISTS") && len(args) > 0 && args[0] == "totp:ch_used:failure-challenge" {
					challengeReads++
					fail = challengeReads > 1
				}
				if fail {
					peer.WriteError("ERR injected storage failure")
					return true
				}
				return false
			})
			app := fiber.New()
			app.Post("/verify", Verify(st, log))
			app.Post("/revoke", Revoke(st))
			path := "/verify"
			body, _ := json.Marshal(VerifyRequest{Subject: "failure-user", Code: code, ChallengeID: challenge})
			if scenario == "revoke commit" {
				path = "/revoke"
				body = []byte(`{"subject":"failure-user"}`)
			}
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status=%d, want 500", resp.StatusCode)
			}
			var out ErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			if out.OK || out.Reason != "internal_error" {
				t.Fatalf("response=%+v", out)
			}
		})
	}
}

func TestBackupVerificationRejectsChallengeClaimedAfterPrecheck(t *testing.T) {
	st, mr, log := setupHandlerTest(t)
	defer mr.Close()
	oldKey := config.EncryptionKey
	config.EncryptionKey = testEncryptionKey
	t.Cleanup(func() { config.EncryptionKey = oldKey })
	encrypted, err := secret.Encrypt([]byte(testEncryptionKey), "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveCredential(context.Background(), &store.Credential{Subject: "racing-subject", Enabled: true, SecretEnc: encrypted, Period: 30, Digits: 6}); err != nil {
		t.Fatal(err)
	}
	const code = "AAAA-BBBB-CCCC-DDDD"
	if err := st.SaveBackupCodes(context.Background(), "racing-subject", []store.BackupCodeEntry{{CodeHash: secure.GetSHA256Hash(normalizeBackupCode(code))}}); err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	mr.Server().SetPreHook(func(peer *server.Peer, command string, args ...string) bool {
		if strings.EqualFold(command, "EXISTS") && len(args) > 0 && args[0] == "totp:ch_used:racing-challenge" && reads.Add(1) == 2 {
			if err := mr.Set(args[0], "1"); err != nil {
				peer.WriteError("ERR concurrent claim injection failed")
				return true
			}
		}
		return false
	})
	app := fiber.New()
	app.Post("/verify", Verify(st, log))
	payload, _ := json.Marshal(VerifyRequest{Subject: "racing-subject", Code: code, ChallengeID: "racing-challenge"})
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	response, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var out VerifyErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 400 || out.OK || out.Reason != "replay" {
		t.Fatalf("racing challenge response=%d %+v", response.StatusCode, out)
	}
	entries, err := st.GetBackupCodes(context.Background(), "racing-subject")
	if err != nil || len(entries) != 1 || entries[0].UsedAt != 0 {
		t.Fatalf("rejected replay consumed backup code: %+v %v", entries, err)
	}
}
