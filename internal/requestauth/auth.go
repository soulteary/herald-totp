// Package requestauth verifies operation-bound service requests.
package requestauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/soulteary/herald-totp/v2/pkg/heraldtotp"
)

const maxDrift = 60 * time.Second
const nonceTTL = 2*maxDrift + 30*time.Second

// ConsumeNonce must atomically record a fresh key and fail closed on backend errors.
type ConsumeNonce func(context.Context, string, time.Duration) (bool, error)

// Config defines service authentication. API keys never rescue invalid HMAC requests.
type Config struct {
	KeyProvider func(string) string
	Consume     ConsumeNonce
	APIKey      string
	Clock       func() time.Time
}

// New requires v2 HMAC or an independently configured API key.
func New(cfg Config) fiber.Handler {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return func(c fiber.Ctx) error {
		attempted := false
		for _, name := range []string{"X-Signature-Version", "X-Signature", "X-Timestamp", "X-Nonce", "X-Key-Id"} {
			if c.Get(name) != "" {
				attempted = true
				break
			}
		}
		if attempted {
			return verify(c, cfg)
		}
		provided := c.Get("X-API-Key")
		if provided == "" {
			if value, ok := strings.CutPrefix(c.Get("Authorization"), "Bearer "); ok {
				provided = value
			}
		}
		if cfg.APIKey != "" && provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(cfg.APIKey)) == 1 {
			return c.Next()
		}
		return deny(c)
	}
}

func deny(c fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"ok": false, "reason": "unauthorized"})
}

func verify(c fiber.Ctx, cfg Config) error {
	version, signature, ts, service, keyID, nonce := c.Get("X-Signature-Version"), c.Get("X-Signature"), c.Get("X-Timestamp"), c.Get("X-Service"), c.Get("X-Key-Id"), c.Get("X-Nonce")
	if version != heraldtotp.SignatureVersion || len(signature) != 64 || len(nonce) != 32 || len(service) == 0 || len(service) > heraldtotp.MaxAuthIdentifierBytes || len(keyID) > heraldtotp.MaxAuthIdentifierBytes || len(ts) > 20 || cfg.KeyProvider == nil || cfg.Consume == nil {
		return deny(c)
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return deny(c)
	}
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	now := cfg.Clock().Unix()
	drift := int64(maxDrift / time.Second)
	if err != nil || timestamp < now-drift || timestamp > now+drift {
		return deny(c)
	}
	secret := cfg.KeyProvider(keyID)
	if secret == "" {
		return deny(c)
	}
	expected := heraldtotp.SignV2(secret, heraldtotp.RequestSignature{Method: c.Method(), Path: string(c.Request().URI().PathOriginal()), Query: string(c.Request().URI().QueryString()), KeyID: keyID, Timestamp: ts, Service: service, Nonce: nonce, Body: c.Body()})
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return deny(c)
	}
	// Bind replay state to the actual credential, signed service and nonce.
	// Different key-ID aliases for the same secret cannot split replay state.
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("totp-auth-nonce:v2\n" + strconv.Itoa(len(service)) + "\n" + service + "\n" + nonce))
	fresh, err := cfg.Consume(c.Context(), "totp:auth:nonce:"+hex.EncodeToString(mac.Sum(nil)), nonceTTL)
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"ok": false, "reason": "authentication_unavailable"})
	}
	if !fresh {
		return deny(c)
	}
	return c.Next()
}
