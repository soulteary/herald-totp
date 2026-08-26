package redistls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Defaults(t *testing.T) {
	cfg, err := Config("redis.internal", "", false)
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ServerName != "redis.internal" || cfg.InsecureSkipVerify {
		t.Fatalf("unexpected TLS config: %+v", cfg)
	}
	if Dialer(cfg) == nil {
		t.Fatal("Dialer returned nil")
	}
}

func TestConfig_CAErrors(t *testing.T) {
	if _, err := Config("", filepath.Join(t.TempDir(), "missing.pem"), false); err == nil {
		t.Fatal("Config missing CA file: expected error")
	}
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Config("", path, false); err == nil {
		t.Fatal("Config invalid CA file: expected error")
	}
}
