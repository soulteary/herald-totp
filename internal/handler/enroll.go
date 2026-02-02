package handler

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	logger "github.com/soulteary/logger-kit"
	secure "github.com/soulteary/secure-kit"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/secret"
	"github.com/soulteary/herald-totp/internal/store"
	"github.com/soulteary/herald-totp/internal/totp"
)

// EnrollStartRequest is the request body for POST /v1/enroll/start.
type EnrollStartRequest struct {
	Subject string `json:"subject"`
	Label   string `json:"label"`
}

// EnrollStartResponse is the response for POST /v1/enroll/start.
type EnrollStartResponse struct {
	EnrollID     string `json:"enroll_id"`
	SecretBase32 string `json:"secret_base32,omitempty"`
	OtpauthURI   string `json:"otpauth_uri"`
}

// EnrollConfirmRequest is the request body for POST /v1/enroll/confirm.
type EnrollConfirmRequest struct {
	EnrollID string `json:"enroll_id"`
	Code     string `json:"code"`
}

// EnrollConfirmResponse is the response for POST /v1/enroll/confirm.
type EnrollConfirmResponse struct {
	Subject     string   `json:"subject"`
	TotpEnabled bool     `json:"totp_enabled"`
	BackupCodes []string `json:"backup_codes,omitempty"`
}

// EnrollStart handles POST /v1/enroll/start.
func EnrollStart(st *store.Store, log *logger.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req EnrollStartRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "invalid_request", "message": err.Error(),
			})
		}
		if req.Subject == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "invalid_request", "message": "subject is required",
			})
		}
		if req.Label == "" {
			req.Label = req.Subject
		}

		keyBytes, err := secret.KeyBytes(config.EncryptionKey)
		if err != nil || len(config.EncryptionKey) < 32 {
			log.Warn().Msg("HERALD_TOTP_ENCRYPTION_KEY not set or invalid (need 32 bytes)")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "config_error", "message": "encryption not configured",
			})
		}

		// Rate limit by subject
		subjectCount, _ := st.IncrRateSubject(c.Context(), req.Subject)
		if subjectCount > int64(config.RateLimitPerSubject) {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"ok": false, "reason": "rate_limited",
			})
		}
		ipCount, _ := st.IncrRateIP(c.Context(), c.IP())
		if ipCount > int64(config.RateLimitPerIP) {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"ok": false, "reason": "rate_limited",
			})
		}

		cfg := totp.Config{
			Issuer: config.TOTPIssuer,
			Period: uint(config.TOTPPeriod),
			Digits: totp.DigitsFromInt(config.TOTPDigits),
			Algo:   totp.AlgorithmSHA1,
			Skew:   uint(config.TOTPSkew),
		}
		secretBase32, otpauthURI, err := totp.Generate(req.Label, cfg)
		if err != nil {
			log.Warn().Err(err).Str("subject", secure.MaskString(req.Subject, 4)).Msg("enroll start: generate failed")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}

		enrollID, err := NewEnrollID()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}

		secretEnc, err := secret.Encrypt(keyBytes, secretBase32)
		if err != nil {
			log.Warn().Err(err).Msg("enroll start: encrypt failed")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}

		now := time.Now()
		expiresAt := now.Add(config.EnrollTTL).Unix()
		e := &store.Enrollment{
			EnrollID:  enrollID,
			Subject:   req.Subject,
			SecretEnc: secretEnc,
			Issuer:    config.TOTPIssuer,
			Label:     req.Label,
			Period:    uint(config.TOTPPeriod),
			Digits:    config.TOTPDigits,
			ExpiresAt: expiresAt,
			CreatedAt: now.Unix(),
		}
		if err := st.SaveEnrollment(c.Context(), e); err != nil {
			log.Warn().Err(err).Msg("enroll start: save failed")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}

		return c.JSON(EnrollStartResponse{
			EnrollID:     enrollID,
			SecretBase32: secretBase32,
			OtpauthURI:   otpauthURI,
		})
	}
}

// EnrollConfirm handles POST /v1/enroll/confirm.
func EnrollConfirm(st *store.Store, log *logger.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req EnrollConfirmRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "invalid_request", "message": err.Error(),
			})
		}
		if req.EnrollID == "" || req.Code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "invalid_request", "message": "enroll_id and code are required",
			})
		}

		keyBytes, err := secret.KeyBytes(config.EncryptionKey)
		if err != nil || len(config.EncryptionKey) < 32 {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "config_error",
			})
		}

		e, err := st.GetEnrollment(c.Context(), req.EnrollID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}
		if e == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "expired", "message": "enrollment not found or expired",
			})
		}

		secretPlain, err := secret.Decrypt(keyBytes, e.SecretEnc)
		if err != nil {
			log.Warn().Err(err).Msg("enroll confirm: decrypt failed")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}

		cfg := totp.Config{
			Issuer: config.TOTPIssuer,
			Period: uint(e.Period),
			Digits: totp.DigitsFromInt(e.Digits),
			Algo:   totp.AlgorithmSHA1,
			Skew:   uint(config.TOTPSkew),
		}
		valid, err := totp.Validate(req.Code, secretPlain, cfg, time.Now())
		if err != nil || !valid {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok": false, "reason": "invalid", "message": "code verification failed",
			})
		}

		now := time.Now()
		cred := &store.Credential{
			Subject:      e.Subject,
			SecretEnc:    e.SecretEnc,
			Issuer:       e.Issuer,
			Label:        e.Label,
			Period:       e.Period,
			Digits:       e.Digits,
			Algo:         "SHA1",
			Enabled:      true,
			LastUsedStep: 0,
			CreatedAt:    now.Unix(),
			UpdatedAt:    now.Unix(),
		}
		if err := st.SaveCredential(c.Context(), cred); err != nil {
			log.Warn().Err(err).Msg("enroll confirm: save credential failed")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "reason": "internal_error",
			})
		}
		_ = st.DeleteEnrollment(c.Context(), req.EnrollID)

		// Optional: generate backup codes (10 single-use codes)
		backupCodes := generateBackupCodes(10)
		entries := make([]store.BackupCodeEntry, len(backupCodes))
		for i, code := range backupCodes {
			entries[i] = store.BackupCodeEntry{CodeHash: secure.GetSHA256Hash(normalizeBackupCode(code)), UsedAt: 0}
		}
		if err := st.SaveBackupCodes(c.Context(), e.Subject, entries); err != nil {
			log.Warn().Err(err).Msg("enroll confirm: save backup codes failed")
		}

		return c.JSON(EnrollConfirmResponse{
			Subject:     e.Subject,
			TotpEnabled: true,
			BackupCodes: backupCodes,
		})
	}
}

// normalizeBackupCode uppercases and removes dash (ABCD-EFGH -> ABCDEFGH).
func normalizeBackupCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
}

// generateBackupCodes returns n human-readable backup codes (e.g. ABCD-EFGH).
func generateBackupCodes(n int) []string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const partLen = 4
	out := make([]string, n)
	for i := 0; i < n; i++ {
		p1, _ := secure.RandomString(partLen, chars)
		p2, _ := secure.RandomString(partLen, chars)
		out[i] = p1 + "-" + p2
	}
	return out
}
