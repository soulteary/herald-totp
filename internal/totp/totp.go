package totp

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// Config holds TOTP generation and validation options.
type Config struct {
	Issuer string
	Period uint
	Digits otp.Digits
	Algo   otp.Algorithm
	Skew   uint
}

// DigitsFromInt returns otp.Digits for 6 or 8.
func DigitsFromInt(n int) otp.Digits {
	if n == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

// AlgorithmSHA1 is the default TOTP algorithm (best compatibility).
var AlgorithmSHA1 = otp.AlgorithmSHA1

// DefaultConfig returns a config with period=30, digits=6, SHA1, skew=1.
func DefaultConfig(issuer string) Config {
	return Config{
		Issuer: issuer,
		Period: 30,
		Digits: otp.DigitsSix,
		Algo:   otp.AlgorithmSHA1,
		Skew:   1,
	}
}

// Generate creates a new TOTP key and returns secret (base32) and otpauth URI.
func Generate(accountName string, cfg Config) (secretBase32, otpauthURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: accountName,
		Period:      cfg.Period,
		Digits:      cfg.Digits,
		Algorithm:   cfg.Algo,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// Validate verifies the code against the secret at the given time.
func Validate(code, secretBase32 string, cfg Config, now time.Time) (bool, error) {
	valid, _, err := ValidateWithStep(code, secretBase32, cfg, now)
	return valid, err
}

// ValidateWithStep verifies the code and returns the exact counter that
// matched. Callers use the matched counter, rather than the server's current
// counter, when enforcing one-time use across the configured skew window.
func ValidateWithStep(code, secretBase32 string, cfg Config, now time.Time) (bool, int64, error) {
	period := cfg.Period
	if period == 0 {
		period = 30
	}
	current := TimeStep(now, period)
	counters := make([]int64, 0, 1+2*int(cfg.Skew))
	counters = append(counters, current)
	for offset := int64(1); offset <= int64(cfg.Skew); offset++ {
		counters = append(counters, current+offset)
		if current >= offset {
			counters = append(counters, current-offset)
		}
	}

	for _, counter := range counters {
		valid, err := hotp.ValidateCustom(code, uint64(counter), secretBase32, hotp.ValidateOpts{
			Digits:    cfg.Digits,
			Algorithm: cfg.Algo,
		})
		if err != nil {
			return false, 0, err
		}
		if valid {
			return true, counter, nil
		}
	}
	return false, 0, nil
}

// TimeStep returns the current time step (Unix / period) for replay check.
func TimeStep(now time.Time, period uint) int64 {
	return now.Unix() / int64(period)
}
