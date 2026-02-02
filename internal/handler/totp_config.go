package handler

import (
	"github.com/soulteary/herald-totp/internal/config"
	"github.com/soulteary/herald-totp/internal/store"
	"github.com/soulteary/herald-totp/internal/totp"
)

// totpConfigFromConfig returns TOTP config from global config (for enroll start/confirm).
func totpConfigFromConfig() totp.Config {
	return totp.Config{
		Issuer: config.TOTPIssuer,
		Period: uint(config.TOTPPeriod),
		Digits: totp.DigitsFromInt(config.TOTPDigits),
		Algo:   totp.AlgorithmSHA1,
		Skew:   uint(config.TOTPSkew),
	}
}

// totpConfigFromCred returns TOTP config from a stored credential (for verify).
func totpConfigFromCred(cred *store.Credential) totp.Config {
	return totp.Config{
		Issuer: config.TOTPIssuer,
		Period: uint(cred.Period),
		Digits: totp.DigitsFromInt(cred.Digits),
		Algo:   totp.AlgorithmSHA1,
		Skew:   uint(config.TOTPSkew),
	}
}
