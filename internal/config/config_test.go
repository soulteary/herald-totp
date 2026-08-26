package config

import (
	"os"
	"testing"

	logger "github.com/soulteary/logger-kit/v2"
)

func TestInitialize(t *testing.T) {
	l := logger.New(logger.Config{Level: logger.Disabled})
	Initialize(l)
	if log != l {
		t.Fatal("logger should be set")
	}
}

func TestInitialize_HMACKeys(t *testing.T) {
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
	Initialize(logger.New(logger.Config{Level: logger.Disabled}))

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
	oldJSON, oldMap, oldSingle := HMACKeysJSON, hmacKeysMap, hmacSingleKeyID
	defer func() {
		HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = oldJSON, oldMap, oldSingle
	}()
	HMACKeysJSON = "{invalid"
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	Initialize(logger.New(logger.Config{Level: logger.Disabled}))
	if HasHMACKeys() {
		t.Fatal("invalid JSON should not configure HMAC keys")
	}
}

func TestInitialize_SingleHMACKeyAllowsOmittedKeyID(t *testing.T) {
	oldJSON, oldMap, oldSingle := HMACKeysJSON, hmacKeysMap, hmacSingleKeyID
	defer func() {
		HMACKeysJSON, hmacKeysMap, hmacSingleKeyID = oldJSON, oldMap, oldSingle
	}()
	HMACKeysJSON = `{"only":"secret"}`
	hmacKeysMap = nil
	hmacSingleKeyID = ""
	Initialize(logger.New(logger.Config{Level: logger.Disabled}))
	if got := GetHMACSecret(""); got != "secret" {
		t.Fatalf("GetHMACSecret(without key ID) = %q, want single configured secret", got)
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
