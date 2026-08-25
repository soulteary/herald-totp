package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	logger "github.com/soulteary/logger-kit"
	secure "github.com/soulteary/secure-kit"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/metrics"
	"github.com/soulteary/herald-totp/internal/secret"
	"github.com/soulteary/herald-totp/internal/store"
	"github.com/soulteary/herald-totp/internal/totp"
)

// VerifyRequest is the request body for POST /v1/verify.
type VerifyRequest struct {
	Subject     string `json:"subject"`
	Code        string `json:"code"`
	ChallengeID string `json:"challenge_id"` // optional, for replay/audit
}

// VerifyResponse is the response for POST /v1/verify (success).
type VerifyResponse struct {
	OK       bool     `json:"ok"`
	Subject  string   `json:"subject,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	IssuedAt int64    `json:"issued_at,omitempty"`
}

// VerifyErrorResponse is the error response for verify.
type VerifyErrorResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Verify handles POST /v1/verify.
func Verify(st *store.Store, log *logger.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req VerifyRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid_request",
			})
		}
		if req.Subject == "" || req.Code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid_request",
			})
		}

		// Optional challenge_id replay check
		if req.ChallengeID != "" {
			used, err := st.IsChallengeUsed(c.Context(), req.ChallengeID)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
					OK: false, Reason: "internal_error",
				})
			}
			if used {
				metrics.RecordVerify("failure", "replay")
				return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
					OK: false, Reason: "replay",
				})
			}
		}

		limited, err := rateLimitExceeded(c, st, req.Subject)
		if err != nil {
			log.Warn().Err(err).Msg("verify: rate limit failed")
			metrics.RecordVerify("failure", "internal_error")
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "internal_error",
			})
		}
		if limited {
			metrics.RecordVerify("failure", "rate_limited")
			return c.Status(fiber.StatusTooManyRequests).JSON(VerifyErrorResponse{
				OK: false, Reason: "rate_limited",
			})
		}

		cred, err := st.GetCredential(c.Context(), req.Subject)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "internal_error",
			})
		}
		if cred == nil || !cred.Enabled {
			metrics.RecordVerify("failure", "invalid")
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid",
			})
		}

		keyBytes, err := secret.KeyBytes(config.EncryptionKey)
		if err != nil || len(config.EncryptionKey) < 32 {
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "config_error",
			})
		}
		secretPlain, err := secret.Decrypt(keyBytes, cred.SecretEnc)
		if err != nil {
			log.Warn().Err(err).Str("subject", secure.MaskString(cred.Subject, 4)).Msg("verify: decrypt failed")
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "internal_error",
			})
		}

		cfg := totpConfigFromCred(cred)
		now := time.Now()
		valid, matchedStep, err := totp.ValidateWithStep(req.Code, secretPlain, cfg, now)
		if !valid || err != nil {
			// Try backup code (user might have lost device)
			codeHash := secure.GetSHA256Hash(normalizeBackupCode(req.Code))
			consumed, consumeErr := st.ConsumeBackupCode(c.Context(), req.Subject, codeHash)
			if consumeErr != nil {
				log.Warn().Err(consumeErr).Msg("verify: consume backup code failed")
				return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
					OK: false, Reason: "internal_error",
				})
			}
			if consumed {
				if ok, err := claimChallenge(c, st, req.ChallengeID); err != nil {
					return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{OK: false, Reason: "internal_error"})
				} else if !ok {
					metrics.RecordVerify("failure", "replay")
					return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{OK: false, Reason: "replay"})
				}
				metrics.RecordVerify("success", "backup_code")
				issuedAt := time.Now().Unix()
				return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp", "backup_code"}, IssuedAt: issuedAt})
			}
			metrics.RecordVerify("failure", "invalid")
			return c.Status(fiber.StatusUnauthorized).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid",
			})
		}

		claimed, err := st.ClaimCredentialStep(c.Context(), req.Subject, matchedStep, now.Unix())
		if err != nil {
			log.Warn().Err(err).Msg("verify: claim TOTP step failed")
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "internal_error",
			})
		}
		if !claimed {
			metrics.RecordVerify("failure", "replay")
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
				OK: false, Reason: "replay",
			})
		}
		if ok, err := claimChallenge(c, st, req.ChallengeID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{OK: false, Reason: "internal_error"})
		} else if !ok {
			metrics.RecordVerify("failure", "replay")
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{OK: false, Reason: "replay"})
		}
		metrics.RecordVerify("success", "totp")
		return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp"}, IssuedAt: now.Unix()})
	}
}

func claimChallenge(c *fiber.Ctx, st *store.Store, challengeID string) (bool, error) {
	if challengeID == "" {
		return true, nil
	}
	return st.ClaimChallenge(c.Context(), challengeID)
}
