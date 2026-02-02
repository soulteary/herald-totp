package handler

import (
	"github.com/gofiber/fiber/v2"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/store"
)

// RevokeRequest is the request body for POST /v1/revoke.
type RevokeRequest struct {
	Subject string `json:"subject"`
}

// RevokeResponse is the response for POST /v1/revoke.
type RevokeResponse struct {
	OK      bool   `json:"ok"`
	Subject string `json:"subject"`
}

// Revoke handles POST /v1/revoke: remove TOTP credential and backup codes for the subject.
func Revoke(st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req RevokeRequest
		if err := c.BodyParser(&req); err != nil {
			return respondBadRequest(c, "invalid_request", err.Error())
		}
		if req.Subject == "" {
			return respondBadRequest(c, "invalid_request", "subject is required")
		}

		subjectCount, _ := st.IncrRateSubject(c.Context(), req.Subject)
		if subjectCount > int64(config.RateLimitPerSubject) {
			return respondRateLimited(c)
		}
		ipCount, _ := st.IncrRateIP(c.Context(), c.IP())
		if ipCount > int64(config.RateLimitPerIP) {
			return respondRateLimited(c)
		}

		_ = st.DeleteCredential(c.Context(), req.Subject)
		_ = st.DeleteBackupCodes(c.Context(), req.Subject)
		return c.JSON(RevokeResponse{OK: true, Subject: req.Subject})
	}
}
