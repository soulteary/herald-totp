package config

import (
	"os"
	"testing"

	logger "github.com/soulteary/logger-kit"
)

func TestInitialize(t *testing.T) {
	log := logger.New(logger.Config{Level: logger.Disabled})
	Initialize(log)
	if log == nil {
		t.Fatal("logger should be set")
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
	_ = AllowNoAuth()
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
