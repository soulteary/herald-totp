package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/soulteary/herald-totp/v2/internal/config"
	"github.com/soulteary/herald-totp/v2/internal/store"
)

func rateLimitExceeded(c fiber.Ctx, st *store.Store, subject string) (bool, error) {
	limited, err := subjectRateLimitExceeded(c, st, subject)
	if err != nil || limited {
		return limited, err
	}
	return ipRateLimitExceeded(c, st)
}

func subjectRateLimitExceeded(c fiber.Ctx, st *store.Store, subject string) (bool, error) {
	count, err := st.IncrRateSubject(c.Context(), subject)
	return count > int64(config.RateLimitPerSubject), err
}

func ipRateLimitExceeded(c fiber.Ctx, st *store.Store) (bool, error) {
	count, err := st.IncrRateIP(c.Context(), c.IP())
	return count > int64(config.RateLimitPerIP), err
}
