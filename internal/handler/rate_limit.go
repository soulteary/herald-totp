package handler

import (
	"github.com/gofiber/fiber/v2"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/store"
)

func rateLimitExceeded(c *fiber.Ctx, st *store.Store, subject string) (bool, error) {
	subjectCount, err := st.IncrRateSubject(c.Context(), subject)
	if err != nil {
		return false, err
	}
	if subjectCount > int64(config.RateLimitPerSubject) {
		return true, nil
	}

	ipCount, err := st.IncrRateIP(c.Context(), c.IP())
	if err != nil {
		return false, err
	}
	return ipCount > int64(config.RateLimitPerIP), nil
}
