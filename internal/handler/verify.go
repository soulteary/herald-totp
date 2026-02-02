package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	logger "github.com/soulteary/logger-kit"
	secure "github.com/soulteary/secure-kit"

	"github.com/soulteary/herald-totp/internal/config"
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
				return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
					OK: false, Reason: "replay",
				})
			}
		}

		// Rate limit
		subjectCount, _ := st.IncrRateSubject(c.Context(), req.Subject)
		if subjectCount > int64(config.RateLimitPerSubject) {
			return c.Status(fiber.StatusTooManyRequests).JSON(VerifyErrorResponse{
				OK: false, Reason: "rate_limited",
			})
		}
		ipCount, _ := st.IncrRateIP(c.Context(), c.IP())
		if ipCount > int64(config.RateLimitPerIP) {
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
		valid, err := totp.Validate(req.Code, secretPlain, cfg, now)
		if !valid || err != nil {
			// Try backup code (user might have lost device)
			codeHash := secure.GetSHA256Hash(normalizeBackupCode(req.Code))
			consumed, _ := st.ConsumeBackupCode(c.Context(), req.Subject, codeHash)
			if consumed {
				if req.ChallengeID != "" {
					_ = st.MarkChallengeUsed(c.Context(), req.ChallengeID)
				}
				issuedAt := time.Now().Unix()
				return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp", "backup_code"}, IssuedAt: issuedAt})
			}
			return c.Status(fiber.StatusUnauthorized).JSON(VerifyErrorResponse{
				OK: false, Reason: "invalid",
			})
		}

		step := totp.TimeStep(now, uint(cred.Period))
		if step <= cred.LastUsedStep {
			return c.Status(fiber.StatusBadRequest).JSON(VerifyErrorResponse{
				OK: false, Reason: "replay",
			})
		}

		cred.LastUsedStep = step
		cred.UpdatedAt = now.Unix()
		if err := st.SaveCredential(c.Context(), cred); err != nil {
			log.Warn().Err(err).Msg("verify: save credential failed")
			return c.Status(fiber.StatusInternalServerError).JSON(VerifyErrorResponse{
				OK: false, Reason: "internal_error",
			})
		}
		if req.ChallengeID != "" {
			_ = st.MarkChallengeUsed(c.Context(), req.ChallengeID)
		}
		return c.JSON(VerifyResponse{OK: true, Subject: req.Subject, AMR: []string{"totp"}, IssuedAt: now.Unix()})
	}
}
