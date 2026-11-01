package main

import (
	"bytes"
	"github.com/alicebob/miniredis/v2"
	"github.com/soulteary/herald-totp/internal/config"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pterm/pterm"
)

func TestShowBanner(t *testing.T) {
	var output bytes.Buffer
	pterm.SetDefaultOutput(&output)
	defer pterm.SetDefaultOutput(os.Stdout)

	showBanner()
	if got := output.String(); !strings.Contains(got, "Herald TOTP") || !strings.Contains(got, "TOTP 2FA Service") {
		t.Fatalf("banner output = %q", got)
	}
}

// Exercise the real entrypoint, including signal-driven graceful shutdown.
func TestMainLifecycle(t *testing.T) {
	oldPort, oldAddr, oldKey, oldAPIKey := config.Port, config.RedisAddr, config.EncryptionKey, config.APIKey
	t.Cleanup(func() {
		config.Port, config.RedisAddr, config.EncryptionKey, config.APIKey = oldPort, oldAddr, oldKey, oldAPIKey
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	config.Port = strings.TrimPrefix(address, "127.0.0.1")
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	config.RedisAddr = mr.Addr()
	config.EncryptionKey = "0123456789abcdef0123456789abcdef"
	config.APIKey = "test-api-key"
	done := make(chan struct{})
	go func() { main(); close(done) }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("health status = %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
	if resp, err := client.Get("http://" + address + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("server accepts requests after shutdown")
	}
}
