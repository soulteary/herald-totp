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
			return respondBadRequest(c, "invalid_request", err.Error())
		}
		if req.Subject == "" {
			return respondBadRequest(c, "invalid_request", "subject is required")
		}
		if req.Label == "" {
			req.Label = req.Subject
		}

		keyBytes, err := secret.KeyBytes(config.EncryptionKey)
		if err != nil || len(config.EncryptionKey) < 32 {
			log.Warn().Msg("HERALD_TOTP_ENCRYPTION_KEY not set or invalid (need 32 bytes)")
			return respondConfigError(c, "encryption not configured")
		}

		subjectCount, _ := st.IncrRateSubject(c.Context(), req.Subject)
		if subjectCount > int64(config.RateLimitPerSubject) {
			return respondRateLimited(c)
		}
		ipCount, _ := st.IncrRateIP(c.Context(), c.IP())
		if ipCount > int64(config.RateLimitPerIP) {
			return respondRateLimited(c)
		}

		cfg := totpConfigFromConfig()
		secretBase32, otpauthURI, err := totp.Generate(req.Label, cfg)
		if err != nil {
			log.Warn().Err(err).Str("subject", secure.MaskString(req.Subject, 4)).Msg("enroll start: generate failed")
			return respondInternalError(c)
		}

		enrollID, err := NewEnrollID()
		if err != nil {
			return respondInternalError(c)
		}

		secretEnc, err := secret.Encrypt(keyBytes, secretBase32)
		if err != nil {
			log.Warn().Err(err).Msg("enroll start: encrypt failed")
			return respondInternalError(c)
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
			return respondInternalError(c)
		}

		resp := EnrollStartResponse{EnrollID: enrollID, OtpauthURI: otpauthURI}
		if config.ExposeSecretInEnroll {
			resp.SecretBase32 = secretBase32
		}
		return c.JSON(resp)
	}
}

// EnrollConfirm handles POST /v1/enroll/confirm.
func EnrollConfirm(st *store.Store, log *logger.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req EnrollConfirmRequest
		if err := c.BodyParser(&req); err != nil {
			return respondBadRequest(c, "invalid_request", err.Error())
		}
		if req.EnrollID == "" || req.Code == "" {
			return respondBadRequest(c, "invalid_request", "enroll_id and code are required")
		}

		keyBytes, err := secret.KeyBytes(config.EncryptionKey)
		if err != nil || len(config.EncryptionKey) < 32 {
			return respondConfigError(c, "")
		}

		e, err := st.GetEnrollment(c.Context(), req.EnrollID)
		if err != nil {
			return respondInternalError(c)
		}
		if e == nil {
			return respondBadRequest(c, "expired", "enrollment not found or expired")
		}

		secretPlain, err := secret.Decrypt(keyBytes, e.SecretEnc)
		if err != nil {
			log.Warn().Err(err).Msg("enroll confirm: decrypt failed")
			return respondInternalError(c)
		}

		cfg := totpConfigFromConfig()
		cfg.Period = uint(e.Period)
		cfg.Digits = totp.DigitsFromInt(e.Digits)
		valid, err := totp.Validate(req.Code, secretPlain, cfg, time.Now())
		if err != nil || !valid {
			return respondBadRequest(c, "invalid", "code verification failed")
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
			return respondInternalError(c)
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
