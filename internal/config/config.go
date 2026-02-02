package config

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/soulteary/cli-kit/env"
	logger "github.com/soulteary/logger-kit"
)

var log *logger.Logger

var (
	Port     = env.Get("PORT", ":8084")
	LogLevel = env.Get("LOG_LEVEL", "info")

	// Redis
	RedisAddr     = env.Get("REDIS_ADDR", "localhost:6379")
	RedisPassword = env.Get("REDIS_PASSWORD", "")
	RedisDB       = env.GetInt("REDIS_DB", 0)

	// TOTP
	TOTPIssuer = env.Get("TOTP_ISSUER", "Herald")
	TOTPPeriod = env.GetInt("TOTP_PERIOD", 30)
	TOTPDigits = env.GetInt("TOTP_DIGITS", 6)
	TOTPSkew   = env.GetUint("TOTP_SKEW", 1)

	// Enrollment TTL (temp binding state)
	EnrollTTL = env.GetDuration("ENROLL_TTL", 10*time.Minute)

	// Secret encryption (32 bytes for AES-256)
	EncryptionKey = env.Get("HERALD_TOTP_ENCRYPTION_KEY", "")

	// Service auth: API Key or HMAC
	APIKey       = env.Get("API_KEY", "")
	HMACSecret   = env.Get("HMAC_SECRET", "")
	HMACKeysJSON = env.Get("HERALD_TOTP_HMAC_KEYS", "")
	ServiceName  = env.Get("SERVICE_NAME", "herald-totp")

	hmacKeysMap      map[string]string
	hmacDefaultKeyID string

	// Rate limit
	RateLimitPerSubject = env.GetInt("RATE_LIMIT_PER_SUBJECT", 20) // per hour
	RateLimitPerIP      = env.GetInt("RATE_LIMIT_PER_IP", 30)      // per minute

	// Enroll response: when false, do not return secret_base32 (only otpauth_uri for QR)
	ExposeSecretInEnroll = ParseBoolEnv("EXPOSE_SECRET_IN_ENROLL", true)
)

// Initialize sets the logger and parses HMAC keys if present.
func Initialize(l *logger.Logger) {
	log = l
	if HMACKeysJSON != "" {
		if err := parseHMACKeys(); err != nil {
			log.Warn().Err(err).Msg("Failed to parse HERALD_TOTP_HMAC_KEYS")
		} else {
			for keyID := range hmacKeysMap {
				hmacDefaultKeyID = keyID
				break
			}
		}
	}
}

func parseHMACKeys() error {
	return json.Unmarshal([]byte(HMACKeysJSON), &hmacKeysMap)
}

// ParseBoolEnv reads an env var as bool: "true"/"1"/"yes" (case-insensitive) = true, "false"/"0"/etc = false, empty = defaultVal.
func ParseBoolEnv(key string, defaultVal bool) bool {
	v := strings.ToLower(strings.TrimSpace(env.Get(key, "")))
	if v == "" {
		return defaultVal
	}
	return v == "true" || v == "1" || v == "yes"
}

// GetHMACSecret returns the HMAC secret for the given key ID.
func GetHMACSecret(keyID string) string {
	if len(hmacKeysMap) > 0 {
		if keyID == "" {
			keyID = hmacDefaultKeyID
		}
		if s, ok := hmacKeysMap[keyID]; ok {
			return s
		}
		return ""
	}
	return HMACSecret
}

// HasHMACKeys returns true if multiple HMAC keys are configured.
func HasHMACKeys() bool {
	return len(hmacKeysMap) > 0
}

// AllowNoAuth returns true when no API key or HMAC is set (dev only).
func AllowNoAuth() bool {
	return APIKey == "" && HMACSecret == "" && !HasHMACKeys()
}
