package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"
	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/router"
	"github.com/soulteary/logger-kit"
	version "github.com/soulteary/version-kit"
)

func showBanner() {
	pterm.DefaultBox.Println(
		putils.CenterText(
			"Herald TOTP\n" +
				"TOTP 2FA Service (Enroll / Verify / Backup Codes)\n" +
				"Version: " + version.Version,
		),
	)
	time.Sleep(time.Millisecond)
}

func main() {
	showBanner()

	level := logger.ParseLevelFromEnv("LOG_LEVEL", logger.InfoLevel)
	log := logger.New(logger.Config{
		Level:          level,
		ServiceName:    "herald-totp",
		ServiceVersion: version.Version,
	})
	config.Initialize(log)

	port := config.Port
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}
	if config.EncryptionKey == "" || len(config.EncryptionKey) < 32 {
		log.Warn().Msg("HERALD_TOTP_ENCRYPTION_KEY not set or shorter than 32 bytes; enroll/verify will fail")
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: false})
	st, err := router.Setup(app, log)
	if err != nil {
		log.Fatal().Err(err).Msg("router setup failed")
	}
	_ = st

	go func() {
		if err := app.Listen(port); err != nil {
			log.Fatal().Err(err).Msg("listen failed")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.ShutdownWithContext(ctx); err != nil {
		log.Warn().Err(err).Msg("shutdown error")
	}
}
