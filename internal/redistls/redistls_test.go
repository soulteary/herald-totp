package redistls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestDialerUsesConfiguredTrustAndHonorsCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Config("", path, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("custom trust roots were not loaded")
	}
	conn, err := Dialer(cfg)(context.Background(), "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dialer(cfg)(ctx, "tcp", server.Listener.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("dial error=%v", err)
	}
}

func TestConfigUsesExplicitCAWhenSystemRootsCannotLoad(t *testing.T) {
	if os.Getenv("HERALD_TEST_UNAVAILABLE_SYSTEM_ROOTS") == "1" {
		certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		defer certificateServer.Close()
		caPath := filepath.Join(t.TempDir(), "explicit-ca.pem")
		if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateServer.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Config("", caPath, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := certificateServer.Certificate().Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: "127.0.0.1"}); err != nil {
			t.Fatalf("explicit CA did not establish trust: %v", err)
		}
		return
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux system-root fallback")
	}
	args := []string{"-test.run=^TestConfigUsesExplicitCAWhenSystemRootsCannotLoad$"}
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+coverage.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "HERALD_TEST_UNAVAILABLE_SYSTEM_ROOTS=1", "SSL_CERT_FILE="+t.TempDir(), "SSL_CERT_DIR="+filepath.Join(t.TempDir(), "missing"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("system-root fallback: %v\n%s", err, output)
	}
}
