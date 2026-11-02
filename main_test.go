package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"github.com/alicebob/miniredis/v2"
	"github.com/soulteary/herald-totp/internal/config"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
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
	config.Port = strings.TrimPrefix(address, "127.0.0.1:")
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

func TestMainStartupFailuresExitNonzero(t *testing.T) {
	if scenario := os.Getenv("HERALD_TOTP_TEST_STARTUP_FAILURE"); scenario != "" {
		config.APIKey = "startup-test-key"
		config.EncryptionKey = "0123456789abcdef0123456789abcdef"
		config.Port = "invalid-port"
		switch scenario {
		case "configuration":
			config.EncryptionKey = "invalid-key"
		case "redis":
			config.RedisAddr = "invalid-address"
		case "listen":
			mr := miniredis.RunT(t)
			config.RedisAddr = mr.Addr()
		default:
			t.Fatal("unknown startup failure scenario")
		}
		main()
		t.Fatal("main returned after startup failure")
	}
	for scenario, message := range map[string]string{"configuration": "invalid configuration", "redis": "router setup failed", "listen": "listen failed"} {
		t.Run(scenario, func(t *testing.T) {
			args := []string{"-test.run=^TestMainStartupFailuresExitNonzero$"}
			if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
				args = append(args, "-test.gocoverdir="+coverage.Value.String())
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "HERALD_TOTP_TEST_STARTUP_FAILURE="+scenario)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("exit=%v, output=%s", err, output)
			}
			if !strings.Contains(string(output), message) {
				t.Fatalf("missing %q in startup failure: %s", message, output)
			}
		})
	}
}

type blockedEntropyReader struct {
	delegate         io.Reader
	entered, release chan struct{}
	once             sync.Once
	block            atomic.Bool
}

func (r *blockedEntropyReader) Read(p []byte) (int, error) {
	if !r.block.Load() {
		return r.delegate.Read(p)
	}
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return r.delegate.Read(p)
}

func TestMainBoundsShutdownWhileEnrollmentEntropyIsBlocked(t *testing.T) {
	if os.Getenv("HERALD_TOTP_TEST_BLOCKED_SHUTDOWN") != "1" {
		args := []string{"-test.run=^TestMainBoundsShutdownWhileEnrollmentEntropyIsBlocked$"}
		if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
			args = append(args, "-test.gocoverdir="+coverage.Value.String())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], args...)
		cmd.Env = append(os.Environ(), "HERALD_TOTP_TEST_BLOCKED_SHUTDOWN=1")
		output, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("shutdown must exit 1: err=%v context=%v\n%s", err, ctx.Err(), output)
		}
		if !strings.Contains(string(output), "shutdown error") || !strings.Contains(string(output), "context deadline exceeded") {
			t.Fatalf("missing shutdown deadline diagnostic: %s", output)
		}
		return
	}
	mr := miniredis.RunT(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	config.Port = strings.TrimPrefix(address, "127.0.0.1:")
	config.RedisAddr = mr.Addr()
	config.EncryptionKey = "0123456789abcdef0123456789abcdef"
	config.APIKey = "shutdown-test-key"
	entropy := &blockedEntropyReader{delegate: rand.Reader, entered: make(chan struct{}), release: make(chan struct{})}
	rand.Reader = entropy
	mainDone := make(chan struct{})
	go func() { main(); close(mainDone) }()
	client := &http.Client{Timeout: 30 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("health=%d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	entropy.block.Store(true)
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, err := http.NewRequest(http.MethodPost, "http://"+address+"/v1/enroll/start", strings.NewReader(`{"subject":"shutdown-entropy-test"}`))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "shutdown-test-key")
		response, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
	}()
	select {
	case <-entropy.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment did not reach random source")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Before the fix main returns here with success; the parent must reject that exit.
	select {
	case <-mainDone:
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown deadline not enforced")
	}
	close(entropy.release)
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}
}
