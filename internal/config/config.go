package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/soulteary/cli-kit/env"
	logger "github.com/soulteary/logger-kit/v2"
)

var log *logger.Logger

var (
	Port     = env.Get("PORT", ":8084")
	LogLevel = env.Get("LOG_LEVEL", "info")

	// Redis
	RedisAddr                  = env.Get("REDIS_ADDR", "localhost:6379")
	RedisPassword              = env.Get("REDIS_PASSWORD", "")
	RedisDB                    = env.GetInt("REDIS_DB", 0)
	RedisTLSEnabled            = ParseBoolEnv("REDIS_TLS_ENABLED", false)
	RedisTLSServerName         = env.Get("REDIS_TLS_SERVER_NAME", "")
	RedisTLSCAFile             = env.Get("REDIS_TLS_CA_FILE", "")
	RedisTLSInsecureSkipVerify = ParseBoolEnv("REDIS_TLS_INSECURE_SKIP_VERIFY", false)

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

	hmacKeysMap     map[string]string
	hmacSingleKeyID string

	// Rate limit
	RateLimitPerSubject = env.GetInt("RATE_LIMIT_PER_SUBJECT", 20) // per hour
	RateLimitPerIP      = env.GetInt("RATE_LIMIT_PER_IP", 30)      // per minute

	// Enroll response: when false, do not return secret_base32 (only otpauth_uri for QR)
	ExposeSecretInEnroll = ParseBoolEnv("EXPOSE_SECRET_IN_ENROLL", true)
)

// Initialize sets the logger, parses HMAC keys, and validates all service
// configuration before external resources are initialized.
func Initialize(l *logger.Logger) error {
	log = l
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	var parseErr error
	if HMACKeysJSON != "" {
		parsed, err := parseHMACKeys(HMACKeysJSON)
		if err != nil {
			parseErr = fmt.Errorf("parse HERALD_TOTP_HMAC_KEYS: %w", err)
		} else {
			hmacKeysMap = parsed
			if len(hmacKeysMap) == 1 {
				for keyID := range hmacKeysMap {
					hmacSingleKeyID = keyID
				}
			}
		}
	}
	return errors.Join(parseErr, Validate())
}

func parseHMACKeys(raw string) (map[string]string, error) {
	keys := make(map[string]string)
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// Validate checks configuration invariants that would otherwise make the
// service unavailable, unsafe, or unexpectedly expensive at runtime.
func Validate() error {
	var problems []string
	if strings.TrimSpace(Port) == "" || strings.TrimSpace(Port) == ":" {
		problems = append(problems, "PORT must not be empty")
	}
	if strings.TrimSpace(RedisAddr) == "" {
		problems = append(problems, "REDIS_ADDR must not be empty")
	}
	if RedisDB < 0 {
		problems = append(problems, "REDIS_DB must be non-negative")
	}
	if !RedisTLSEnabled && (RedisTLSServerName != "" || RedisTLSCAFile != "" || RedisTLSInsecureSkipVerify) {
		problems = append(problems, "Redis TLS options require REDIS_TLS_ENABLED=true")
	}
	if strings.TrimSpace(TOTPIssuer) == "" {
		problems = append(problems, "TOTP_ISSUER must not be empty")
	}
	if TOTPPeriod <= 0 || TOTPPeriod > 300 {
		problems = append(problems, "TOTP_PERIOD must be between 1 and 300 seconds")
	}
	if TOTPDigits != 6 && TOTPDigits != 8 {
		problems = append(problems, "TOTP_DIGITS must be 6 or 8")
	}
	if TOTPSkew > 10 {
		problems = append(problems, "TOTP_SKEW must not exceed 10 steps")
	}
	if EnrollTTL <= 0 {
		problems = append(problems, "ENROLL_TTL must be positive")
	}
	if len(EncryptionKey) != 32 {
		problems = append(problems, "HERALD_TOTP_ENCRYPTION_KEY must be exactly 32 bytes")
	}
	if RateLimitPerSubject <= 0 {
		problems = append(problems, "RATE_LIMIT_PER_SUBJECT must be positive")
	}
	if RateLimitPerIP <= 0 {
		problems = append(problems, "RATE_LIMIT_PER_IP must be positive")
	}
	if HMACKeysJSON != "" {
		if len(hmacKeysMap) == 0 {
			problems = append(problems, "HERALD_TOTP_HMAC_KEYS must contain at least one key")
		}
		for keyID, secret := range hmacKeysMap {
			if strings.TrimSpace(keyID) == "" {
				problems = append(problems, "HERALD_TOTP_HMAC_KEYS contains an empty key ID")
			}
			if secret == "" {
				problems = append(problems, fmt.Sprintf("HERALD_TOTP_HMAC_KEYS key %q has an empty secret", keyID))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return nil
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
			// Omitting X-Key-Id is unambiguous only when exactly one mapped
			// key exists. Multiple keys always require an explicit key ID.
			keyID = hmacSingleKeyID
			if keyID == "" {
				return ""
			}
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
