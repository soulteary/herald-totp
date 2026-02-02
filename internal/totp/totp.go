package totp

import (
	"time"

	"github.com/pquerna/otp"
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
	return totp.ValidateCustom(code, secretBase32, now, totp.ValidateOpts{
		Period:    cfg.Period,
		Skew:      cfg.Skew,
		Digits:    cfg.Digits,
		Algorithm: cfg.Algo,
	})
}

// TimeStep returns the current time step (Unix / period) for replay check.
func TimeStep(now time.Time, period uint) int64 {
	return now.Unix() / int64(period)
}
