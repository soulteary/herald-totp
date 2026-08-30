package handler

import (
	"time"

	"github.com/gofiber/fiber/v3"
	logger "github.com/soulteary/logger-kit/v2"
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
	return func(c fiber.Ctx) error {
		var req VerifyRequest
		if err := c.Bind().Body(&req); err != nil {
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
			consumed, consumeErr := st.ConsumeBackupCodeAndClaimChallenge(c.Context(), req.Subject, codeHash, req.ChallengeID)
			if consumeErr != nil {
				log.Warn().Err(consumeErr).Msg("verify: consume backup code failed")
				return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
					OK: false, Reason: "internal_error",
				})
			}
			if consumed {
				metrics.RecordVerify("success", "backup_code")
				issuedAt := time.Now().Unix()
				return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp", "backup_code"}, IssuedAt: issuedAt})
			}
			if req.ChallengeID != "" {
				used, checkErr := st.IsChallengeUsed(c.Context(), req.ChallengeID)
				if checkErr != nil {
					return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{OK: false, Reason: "internal_error"})
				}
				if used {
					metrics.RecordVerify("failure", "replay")
					return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{OK: false, Reason: "replay"})
				}
			}
			metrics.RecordVerify("failure", "invalid")
			return c.Status(fiber.StatusUnauthorized).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid",
			})
		}

		claimed, err := st.ClaimCredentialStepAndChallenge(c.Context(), req.Subject, matchedStep, now.Unix(), req.ChallengeID)
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
		metrics.RecordVerify("success", "totp")
		return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp"}, IssuedAt: now.Unix()})
	}
}

