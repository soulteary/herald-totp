package router

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	health "github.com/soulteary/health-kit"
	logger "github.com/soulteary/logger-kit"
	middlewarekit "github.com/soulteary/middleware-kit"
	rediskit "github.com/soulteary/redis-kit/client"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/handler"
	"github.com/soulteary/herald-totp/internal/store"
)

// Setup creates the Fiber app and mounts routes. Call config.Initialize(log) before this.
func Setup(app *fiber.App, log *logger.Logger) (*store.Store, error) {
	cfg := rediskit.DefaultConfig().
		WithAddr(config.RedisAddr).
		WithPassword(config.RedisPassword).
		WithDB(config.RedisDB)
	redisClient, err := rediskit.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	enrollTTL := config.EnrollTTL
	chUsedTTL := 5 * time.Minute
	rateSubTTL := time.Hour
	rateIPTTL := time.Minute
	st := store.NewStore(redisClient, enrollTTL, 0, chUsedTTL, rateSubTTL, rateIPTTL)

	app.Use(recover.New())
	app.Use(logger.FiberMiddleware(logger.MiddlewareConfig{
		Logger:           log,
		SkipPaths:        []string{"/healthz"},
		IncludeRequestID: true,
		IncludeLatency:   true,
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,OPTIONS",
		AllowHeaders: "Content-Type,Authorization,X-Service,X-Signature,X-Timestamp,X-API-Key,X-Key-Id",
	}))

	healthConfig := health.DefaultConfig().WithServiceName(config.ServiceName)
	healthAgg := health.NewAggregator(healthConfig)
	healthAgg.AddChecker(health.NewRedisChecker(redisClient))
	app.Get("/healthz", health.FiberHandler(healthAgg))

	v1 := app.Group("/v1")
	zerologLogger := log.Zerolog()
	authHandler := middlewarekit.CombinedAuth(middlewarekit.AuthConfig{
		HMACConfig: &middlewarekit.HMACConfig{
			KeyProvider: config.GetHMACSecret,
		},
		APIKeyConfig: &middlewarekit.APIKeyConfig{
			APIKey: config.APIKey,
		},
		AllowNoAuth: config.AllowNoAuth(),
		Logger:      &zerologLogger,
	})

	v1.Post("/enroll/start", authHandler, handler.EnrollStart(st, log))
	v1.Post("/enroll/confirm", authHandler, handler.EnrollConfirm(st, log))
	v1.Post("/verify", authHandler, handler.Verify(st, log))
	v1.Post("/revoke", authHandler, handler.Revoke(st))
	v1.Get("/status", authHandler, handler.Status(st))

	return st, nil
}
