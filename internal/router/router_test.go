package router

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	logger "github.com/soulteary/logger-kit"

	"github.com/soulteary/herald-totp/internal/config"
)

func TestSetup(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	oldAddr := config.RedisAddr
	oldPass := config.RedisPassword
	oldDB := config.RedisDB
	config.RedisAddr = mr.Addr()
	config.RedisPassword = ""
	config.RedisDB = 0
	defer func() {
		config.RedisAddr = oldAddr
		config.RedisPassword = oldPass
		config.RedisDB = oldDB
	}()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	st, err := Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if st == nil {
		t.Fatal("Store is nil")
	}

	// Health check
	req := httptest.NewRequest("GET", "/healthz", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestSetup_RevokeRoute(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	oldAddr := config.RedisAddr
	config.RedisAddr = mr.Addr()
	defer func() { config.RedisAddr = oldAddr }()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	_, err = Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// POST /v1/revoke with empty body: 400 (subject required) when no auth, or 401 when auth required
	req := httptest.NewRequest("POST", "/v1/revoke", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /v1/revoke status = %d, want 400 or 401", resp.StatusCode)
	}
}

func TestSetup_StatusRoute(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	oldAddr := config.RedisAddr
	config.RedisAddr = mr.Addr()
	defer func() { config.RedisAddr = oldAddr }()

	log := logger.New(logger.Config{Level: logger.Disabled})
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	_, err = Setup(app, log)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// GET /v1/status without subject: 400 when no auth, or 401 when auth required
	req := httptest.NewRequest("GET", "/v1/status", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /v1/status status = %d, want 400 or 401", resp.StatusCode)
	}
}
