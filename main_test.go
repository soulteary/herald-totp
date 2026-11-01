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
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), "HERALD_TOTP_TEST_BLOCKED_SHUTDOWN=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("blocked shutdown process: %v\n%s", err, output)
		}
		return
	}
	mr := miniredis.RunT(t)
	oldPort, oldAddr, oldKey, oldAPI := config.Port, config.RedisAddr, config.EncryptionKey, config.APIKey
	oldReader, oldStdout, oldStderr := rand.Reader, os.Stdout, os.Stderr
	output, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logsDone := make(chan struct{})
	go func() { _, _ = io.Copy(&logs, output); close(logsDone) }()
	os.Stdout, os.Stderr = writer, writer
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
	entropy := &blockedEntropyReader{delegate: oldReader, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	mainDone := make(chan struct{})
	requestDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(entropy.release) })
		cancel()
		select {
		case <-mainDone:
		case <-time.After(5 * time.Second):
			t.Error("main remained active during cleanup")
		}
		select {
		case <-requestDone:
		case <-time.After(5 * time.Second):
			t.Error("request remained active during cleanup")
		}
		os.Stdout, os.Stderr = oldStdout, oldStderr
		_ = writer.Close()
		<-logsDone
		_ = output.Close()
		config.Port, config.RedisAddr, config.EncryptionKey, config.APIKey = oldPort, oldAddr, oldKey, oldAPI
	})
	rand.Reader = entropy
	go func() { main(); close(mainDone) }()
	client := &http.Client{Timeout: 30 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("health status=%d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			close(requestDone)
			t.Fatal("server did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	entropy.block.Store(true)
	go func() {
		defer close(requestDone)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/v1/enroll/start", strings.NewReader(`{"subject":"shutdown-entropy-test"}`))
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
	select {
	case <-mainDone:
	case <-time.After(15 * time.Second):
		t.Fatal("main did not enforce shutdown deadline")
	}
	releaseOnce.Do(func() { close(entropy.release) })
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment did not finish after random source resumed")
	}
	_ = writer.Close()
	<-logsDone
	if !strings.Contains(logs.String(), "shutdown error") {
		t.Fatalf("shutdown deadline was not reported: %s", logs.String())
	}
}
