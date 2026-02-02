package handler

import (
	"github.com/gofiber/fiber/v2"

	"github.com/soulteary/herald-totp/internal/store"
)

// StatusResponse is the response for GET /v1/status.
type StatusResponse struct {
	Subject     string `json:"subject"`
	TotpEnabled bool   `json:"totp_enabled"`
}

// Status handles GET /v1/status?subject=xxx.
func Status(st *store.Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		subject := c.Query("subject")
		if subject == "" {
			return respondBadRequest(c, "invalid_request", "subject is required")
		}
		cred, err := st.GetCredential(c.Context(), subject)
		if err != nil {
			return respondInternalError(c)
		}
		enabled := cred != nil && cred.Enabled
		return c.JSON(StatusResponse{
			Subject:     subject,
			TotpEnabled: enabled,
		})
	}
}
