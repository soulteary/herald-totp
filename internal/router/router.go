package router

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"
	health "github.com/soulteary/health-kit/v2"
	logger "github.com/soulteary/logger-kit/v2"
	metricskit "github.com/soulteary/metrics-kit/v2"
	middlewarekit "github.com/soulteary/middleware-kit/v2"
	rediskit "github.com/soulteary/redis-kit/client"

	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/handler"
	"github.com/soulteary/herald-totp/internal/metrics"
	"github.com/soulteary/herald-totp/internal/redistls"
	"github.com/soulteary/herald-totp/internal/store"
)

// Setup creates the Fiber app and mounts routes. Call config.Initialize(log)
// and handle its validation error before this.
func Setup(app *fiber.App, log *logger.Logger) (*store.Store, error) {
	cfg := rediskit.DefaultConfig().
		WithAddr(config.RedisAddr).
		WithPassword(config.RedisPassword).
		WithDB(config.RedisDB)
	if config.RedisTLSEnabled {
		tlsConfig, err := redistls.Config(
			config.RedisTLSServerName,
			config.RedisTLSCAFile,
			config.RedisTLSInsecureSkipVerify,
		)
		if err != nil {
			return nil, err
		}
		cfg.Dialer = redistls.Dialer(tlsConfig)
	}
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
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization", "X-Service", "X-Signature", "X-Timestamp", "X-API-Key", "X-Key-Id"},
	}))

	healthConfig := health.DefaultConfig().WithServiceName(config.ServiceName)
	healthAgg := health.NewAggregator(healthConfig)
	healthAgg.AddChecker(health.NewRedisChecker(redisClient))
	app.Get("/healthz", health.FiberHandler(healthAgg))

	app.Get("/metrics", metricskit.FiberHandlerFor(metrics.Registry))

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
