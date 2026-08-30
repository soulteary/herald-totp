package config

import (
	"os"
	"strings"
	"testing"
	"time"

	logger "github.com/soulteary/logger-kit/v2"
)

func useValidConfig(t *testing.T) {
	t.Helper()
	oldPort, oldAddr, oldDB := Port, RedisAddr, RedisDB
	oldTLSEnabled, oldTLSServerName := RedisTLSEnabled, RedisTLSServerName
	oldTLSCAFile, oldTLSInsecure := RedisTLSCAFile, RedisTLSInsecureSkipVerify
	oldIssuer, oldPeriod, oldDigits, oldSkew := TOTPIssuer, TOTPPeriod, TOTPDigits, TOTPSkew
	oldEnrollTTL, oldEncryptionKey := EnrollTTL, EncryptionKey
	oldSubjectLimit, oldIPLimit := RateLimitPerSubject, RateLimitPerIP
	oldJSON, oldMap, oldSingle := HMACKeysJSON, hmacKeysMap, hmacSingleKeyID
	Port, RedisAddr, RedisDB = ":8084", "localhost:6379", 0
	RedisTLSEnabled, RedisTLSServerName = false, ""
	RedisTLSCAFile, RedisTLSInsecureSkipVerify = "", false
	TOTPIssuer, TOTPPeriod, TOTPDigits, TOTPSkew = "Herald", 30, 6, 1
	EnrollTTL, EncryptionKey = 10*time.Minute, "0123456789abcdef0123456789abcdef"
	RateLimitPerSubject, RateLimitPerIP = 20, 30
	HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = "", nil, ""
	t.Cleanup(func() {
		Port, RedisAddr, RedisDB = oldPort, oldAddr, oldDB
		RedisTLSEnabled, RedisTLSServerName = oldTLSEnabled, oldTLSServerName
		RedisTLSCAFile, RedisTLSInsecureSkipVerify = oldTLSCAFile, oldTLSInsecure
		TOTPIssuer, TOTPPeriod, TOTPDigits, TOTPSkew = oldIssuer, oldPeriod, oldDigits, oldSkew
		EnrollTTL, EncryptionKey = oldEnrollTTL, oldEncryptionKey
		RateLimitPerSubject, RateLimitPerIP = oldSubjectLimit, oldIPLimit
		HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = oldJSON, oldMap, oldSingle
	})
}

func TestInitialize(t *testing.T) {
	useValidConfig(t)
	l := logger.New(logger.Config{Level: logger.Disabled})
	if err := Initialize(l); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if log != l {
		t.Fatal("logger should be set")
	}
}

func TestInitialize_HMACKeys(t *testing.T) {
	useValidConfig(t)
	oldJSON, oldSecret := HMACKeysJSON, HMACSecret
	oldMap, oldSingle := hmacKeysMap, hmacSingleKeyID
	defer func() {
		HMACKeysJSON, HMACSecret = oldJSON, oldSecret
		hmacKeysMap, hmacSingleKeyID = oldMap, oldSingle
	}()

	HMACKeysJSON = `{"primary":"secret-1","secondary":"secret-2"}`
	HMACSecret = "legacy"
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	if err := Initialize(logger.New(logger.Config{Level: logger.Disabled})); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if !HasHMACKeys() {
		t.Fatal("HasHMACKeys = false, want true")
	}
	if got := GetHMACSecret("primary"); got != "secret-1" {
		t.Fatalf("GetHMACSecret(primary) = %q", got)
	}
	if got := GetHMACSecret("missing"); got != "" {
		t.Fatalf("GetHMACSecret(missing) = %q, want empty", got)
	}
	if got := GetHMACSecret(""); got != "" {
		t.Fatalf("GetHMACSecret(without key ID) = %q, want empty for multiple keys", got)
	}
	if AllowNoAuth() {
		t.Fatal("AllowNoAuth = true with configured HMAC keys")
	}
}

func TestInitialize_InvalidHMACKeys(t *testing.T) {
	useValidConfig(t)
	oldJSON, oldMap, oldSingle := HMACKeysJSON, hmacKeysMap, hmacSingleKeyID
	defer func() {
		HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = oldJSON, oldMap, oldSingle
	}()
	HMACKeysJSON = "{invalid"
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	if err := Initialize(logger.New(logger.Config{Level: logger.Disabled})); err == nil {
		t.Fatal("Initialize invalid HMAC JSON: expected error")
	}
	if HasHMACKeys() {
		t.Fatal("invalid JSON should not configure HMAC keys")
	}
}

func TestInitialize_AggregatesHMACParseAndIndependentErrors(t *testing.T) {
	useValidConfig(t)
	HMACKeysJSON = "{invalid"
	Port = ""
	EncryptionKey = "short"

	err := Initialize(logger.New(logger.Config{Level: logger.Disabled}))
	if err == nil {
		t.Fatal("Initialize: expected aggregated error")
	}
	for _, want := range []string{
		"parse HERALD_TOTP_HMAC_KEYS",
		"PORT",
		"HERALD_TOTP_ENCRYPTION_KEY",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Initialize error = %v, want substring %q", err, want)
		}
	}
	if HasHMACKeys() {
		t.Fatal("invalid JSON should leave the parsed key map empty")
	}
}

func TestInitialize_SingleHMACKeyAllowsOmittedKeyID(t *testing.T) {
	useValidConfig(t)
	oldJSON, oldMap, oldSingle := HMACKeysJSON, hmacKeysMap, hmacSingleKeyID
	defer func() {
		HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = oldJSON, oldMap, oldSingle
	}()
	HMACKeysJSON = `{"only":"secret"}`
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	if err := Initialize(logger.New(logger.Config{Level: logger.Disabled})); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if got := GetHMACSecret(""); got != "secret" {
		t.Fatalf("GetHMACSecret(without key ID) = %q, want single configured secret", got)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func()
		want   string
	}{
		{name: "empty port", mutate: func() { Port = "" }, want: "PORT"},
		{name: "empty Redis address", mutate: func() { RedisAddr = "" }, want: "REDIS_ADDR"},
		{name: "negative Redis DB", mutate: func() { RedisDB = -1 }, want: "REDIS_DB"},
		{name: "TLS options without TLS", mutate: func() { RedisTLSCAFile = "ca.pem" }, want: "REDIS_TLS_ENABLED"},
		{name: "empty issuer", mutate: func() { TOTPIssuer = "" }, want: "TOTP_ISSUER"},
		{name: "zero period", mutate: func() { TOTPPeriod = 0 }, want: "TOTP_PERIOD"},
		{name: "large period", mutate: func() { TOTPPeriod = 301 }, want: "TOTP_PERIOD"},
		{name: "invalid digits", mutate: func() { TOTPDigits = 7 }, want: "TOTP_DIGITS"},
		{name: "large skew", mutate: func() { TOTPSkew = 11 }, want: "TOTP_SKEW"},
		{name: "invalid enrollment TTL", mutate: func() { EnrollTTL = 0 }, want: "ENROLL_TTL"},
		{name: "invalid encryption key", mutate: func() { EncryptionKey = "short" }, want: "HERALD_TOTP_ENCRYPTION_KEY"},
		{name: "invalid subject limit", mutate: func() { RateLimitPerSubject = 0 }, want: "RATE_LIMIT_PER_SUBJECT"},
		{name: "invalid IP limit", mutate: func() { RateLimitPerIP = 0 }, want: "RATE_LIMIT_PER_IP"},
		{name: "empty HMAC map", mutate: func() { HMACKeysJSON = "{}"; hmacKeysMap = map[string]string{} }, want: "at least one key"},
		{name: "empty HMAC key ID", mutate: func() { HMACKeysJSON = `{"":"secret"}`; hmacKeysMap = map[string]string{"": "secret"} }, want: "empty key ID"},
		{name: "empty HMAC secret", mutate: func() { HMACKeysJSON = `{"key":""}`; hmacKeysMap = map[string]string{"key": ""} }, want: "empty secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useValidConfig(t)
			tt.mutate()
			err := Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidate_AggregatesProblems(t *testing.T) {
	useValidConfig(t)
	Port = ""
	RedisAddr = ""
	EncryptionKey = "short"
	err := Validate()
	if err == nil {
		t.Fatal("Validate: expected error")
	}
	for _, want := range []string{"PORT", "REDIS_ADDR", "HERALD_TOTP_ENCRYPTION_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate error %q does not contain %q", err, want)
		}
	}
}

func TestGetHMACSecret_NoKeys(t *testing.T) {
	// With no HERALD_TOTP_HMAC_KEYS, hmacKeysMap is empty; GetHMACSecret returns HMACSecret (env default "")
	got := GetHMACSecret("")
	if got != HMACSecret {
		t.Errorf("GetHMACSecret(\"\") = %q, want %q (HMACSecret)", got, HMACSecret)
	}
	got = GetHMACSecret("any-key")
	if got != HMACSecret {
		t.Errorf("GetHMACSecret(\"any-key\") = %q, want HMACSecret", got)
	}
}

func TestHasHMACKeys(t *testing.T) {
	_ = HasHMACKeys()
}

func TestAllowNoAuth(t *testing.T) {
	oldAPIKey, oldHMACSecret, oldMap := APIKey, HMACSecret, hmacKeysMap
	defer func() { APIKey, HMACSecret, hmacKeysMap = oldAPIKey, oldHMACSecret, oldMap }()

	tests := []struct {
		name       string
		apiKey     string
		hmacSecret string
		keys       map[string]string
		want       bool
	}{
		{name: "no auth", want: true},
		{name: "api key", apiKey: "key"},
		{name: "legacy hmac", hmacSecret: "secret"},
		{name: "hmac key map", keys: map[string]string{"key-id": "secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			APIKey, HMACSecret, hmacKeysMap = tt.apiKey, tt.hmacSecret, tt.keys
			if got := AllowNoAuth(); got != tt.want {
				t.Fatalf("AllowNoAuth = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBoolEnv(t *testing.T) {
	key := "HERALD_TOTP_TEST_BOOL_" + t.Name()
	defer func() { _ = os.Unsetenv(key) }()

	// unset -> default true
	if got := ParseBoolEnv(key, true); !got {
		t.Errorf("ParseBoolEnv(unset, true) = false, want true")
	}
	if got := ParseBoolEnv(key, false); got {
		t.Errorf("ParseBoolEnv(unset, false) = true, want false")
	}

	// "true" / "1" / "yes" -> true
	for _, v := range []string{"true", "TRUE", "1", "yes", "YES"} {
		_ = os.Setenv(key, v)
		if got := ParseBoolEnv(key, false); !got {
			t.Errorf("ParseBoolEnv(%q, false) = false, want true", v)
		}
	}

	// "false" / "0" / other -> false
	for _, v := range []string{"false", "FALSE", "0", "no", "x"} {
		_ = os.Setenv(key, v)
		if got := ParseBoolEnv(key, true); got {
			t.Errorf("ParseBoolEnv(%q, true) = true, want false", v)
		}
	}

	// empty string after trim -> default
	_ = os.Setenv(key, "  ")
	if got := ParseBoolEnv(key, true); !got {
		t.Errorf("ParseBoolEnv(space, true) = false, want true")
	}
}
