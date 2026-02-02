package handler

import (
	"github.com/gofiber/fiber/v2"
)

// ErrorResponse is the common error body for API responses (ok, reason, optional message).
type ErrorResponse struct {
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// respondBadRequest sends 400 with reason and message.
func respondBadRequest(c *fiber.Ctx, reason, message string) error {
	return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{OK: false, Reason: reason, Message: message})
}

// respondRateLimited sends 429 with rate_limited reason.
func respondRateLimited(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(ErrorResponse{OK: false, Reason: "rate_limited"})
}

// respondInternalError sends 500 with internal_error reason.
func respondInternalError(c *fiber.Ctx) error {
	return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{OK: false, Reason: "internal_error"})
}

// respondConfigError sends 500 with config_error reason and optional message.
func respondConfigError(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{OK: false, Reason: "config_error", Message: message})
}
