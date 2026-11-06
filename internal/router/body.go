package router

import (
	"github.com/gofiber/fiber/v3"
	"mime"
)

// requireJSON fixes request interpretation before authentication. Signed JSON
// bytes must never be parsed as a form under an unsigned Content-Type change.
func requireJSON(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPost {
		return c.Next()
	}
	media, _, err := mime.ParseMediaType(c.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return c.Status(fiber.StatusUnsupportedMediaType).JSON(fiber.Map{"ok": false, "reason": "json_required"})
	}
	return c.Next()
}
