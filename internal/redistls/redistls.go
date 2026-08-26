package redistls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	rediskit "github.com/soulteary/redis-kit/client"
)

// Config builds the TLS configuration used for Redis connections.
func Config(serverName, caFile string, insecureSkipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // explicit operator-controlled compatibility option
	}
	if caFile == "" {
		return cfg, nil
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Redis TLS CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if ok := roots.AppendCertsFromPEM(pem); !ok {
		return nil, fmt.Errorf("Redis TLS CA file contains no certificates")
	}
	cfg.RootCAs = roots
	return cfg, nil
}

// Dialer adapts a TLS configuration to redis-kit's custom dialer hook.
func Dialer(cfg *tls.Config) rediskit.Dialer {
	dialer := &tls.Dialer{Config: cfg}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}
}
