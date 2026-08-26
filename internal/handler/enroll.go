package handler

import (
	"errors"
	"strings"
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
	return func(c fiber.Ctx) error {
		var req EnrollStartRequest
		if err := c.Bind().Body(&req); err != nil {
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

		limited, err := rateLimitExceeded(c, st, req.Subject)
		if err != nil {
			log.Warn().Err(err).Msg("enroll start: rate limit failed")
			return respondInternalError(c)
		}
		if limited {
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
			if errors.Is(err, store.ErrCredentialExists) {
				return respondConflict(c, "already_enrolled", "subject already has a TOTP credential")
			}
			if errors.Is(err, store.ErrEnrollmentInProgress) {
				return respondConflict(c, "enrollment_in_progress", "subject already has an active enrollment")
			}
			log.Warn().Err(err).Msg("enroll start: save failed")
			return respondInternalError(c)
		}

		metrics.RecordEnrollStart()

		resp := EnrollStartResponse{EnrollID: enrollID, OtpauthURI: otpauthURI}
		if config.ExposeSecretInEnroll {
			resp.SecretBase32 = secretBase32
		}
		return c.JSON(resp)
	}
}

// EnrollConfirm handles POST /v1/enroll/confirm.
func EnrollConfirm(st *store.Store, log *logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		var req EnrollConfirmRequest
		if err := c.Bind().Body(&req); err != nil {
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
			metrics.RecordEnrollConfirm("failure")
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
		valid, matchedStep, err := totp.ValidateWithStep(req.Code, secretPlain, cfg, time.Now())
		if err != nil || !valid {
			metrics.RecordEnrollConfirm("failure")
			return respondBadRequest(c, "invalid", "code verification failed")
		}

		now := time.Now()
		cred := &store.Credential{
			Subject:   e.Subject,
			SecretEnc: e.SecretEnc,
			Issuer:    e.Issuer,
			Label:     e.Label,
			Period:    e.Period,
			Digits:    e.Digits,
			Algo:      "SHA1",
			Enabled:   true,
			// The code used to confirm enrollment is itself a consumed TOTP
			// value. Persist its matched counter so it cannot be reused for an
			// immediate verification request in the same time window.
			LastUsedStep: matchedStep,
			CreatedAt:    now.Unix(),
			UpdatedAt:    now.Unix(),
		}
		// Generate and persist backup codes as part of the enrollment transaction.
		backupCodes := generateBackupCodes(10)
		entries := make([]store.BackupCodeEntry, len(backupCodes))
		for i, code := range backupCodes {
			entries[i] = store.BackupCodeEntry{CodeHash: secure.GetSHA256Hash(normalizeBackupCode(code)), UsedAt: 0}
		}
		confirmed, err := st.ConfirmEnrollment(c.Context(), e, cred, entries)
		if err != nil {
			if errors.Is(err, store.ErrCredentialExists) {
				metrics.RecordEnrollConfirm("failure")
				return respondConflict(c, "already_enrolled", "subject already has a TOTP credential")
			}
			log.Warn().Err(err).Msg("enroll confirm: commit failed")
			metrics.RecordEnrollConfirm("failure")
			return respondInternalError(c)
		}
		if !confirmed {
			metrics.RecordEnrollConfirm("failure")
			return respondBadRequest(c, "expired", "enrollment not found, expired, or already confirmed")
		}
		metrics.RecordEnrollConfirm("success")

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
