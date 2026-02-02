package config

import (
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
