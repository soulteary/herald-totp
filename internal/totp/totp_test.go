package totp

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	pqtotp "github.com/pquerna/otp/totp"
)

func TestDigitsFromInt(t *testing.T) {
	if got := DigitsFromInt(6); got != otp.DigitsSix {
		t.Errorf("DigitsFromInt(6) = %v, want DigitsSix", got)
	}
	if got := DigitsFromInt(8); got != otp.DigitsEight {
		t.Errorf("DigitsFromInt(8) = %v, want DigitsEight", got)
	}
	if got := DigitsFromInt(7); got != otp.DigitsSix {
		t.Errorf("DigitsFromInt(7) = %v, want DigitsSix (default)", got)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("TestIssuer")
	if cfg.Issuer != "TestIssuer" {
		t.Errorf("Issuer = %q, want TestIssuer", cfg.Issuer)
	}
	if cfg.Period != 30 {
		t.Errorf("Period = %d, want 30", cfg.Period)
	}
	if cfg.Digits != otp.DigitsSix {
		t.Errorf("Digits = %v, want DigitsSix", cfg.Digits)
	}
	if cfg.Algo != otp.AlgorithmSHA1 {
		t.Errorf("Algo = %v, want AlgorithmSHA1", cfg.Algo)
	}
	if cfg.Skew != 1 {
		t.Errorf("Skew = %d, want 1", cfg.Skew)
	}
}

func TestGenerate(t *testing.T) {
	cfg := DefaultConfig("TestIssuer")
	secretBase32, otpauthURI, err := Generate("user@example.com", cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if secretBase32 == "" {
		t.Error("secretBase32 is empty")
	}
	if otpauthURI == "" {
		t.Error("otpauthURI is empty")
	}
	if len(secretBase32) < 16 {
		t.Errorf("secretBase32 too short: %d", len(secretBase32))
	}
}

func TestValidate(t *testing.T) {
	cfg := DefaultConfig("TestIssuer")
	secretBase32, _, err := Generate("user@example.com", cfg)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	now := time.Now()
	// Validate with wrong code
	valid, err := Validate("000000", secretBase32, cfg, now)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if valid {
		t.Error("expected invalid code to fail")
	}
	// Generate current code at now using pquerna/otp/totp for valid-code test
	code, err := pqtotp.GenerateCodeCustom(secretBase32, now, pqtotp.ValidateOpts{
		Period: cfg.Period, Skew: cfg.Skew, Digits: cfg.Digits, Algorithm: cfg.Algo,
	})
	if err != nil {
		t.Skipf("skip valid code test: %v", err)
	}
	valid, err = Validate(code, secretBase32, cfg, now)
	if err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	if !valid {
		t.Error("expected valid code to pass")
	}
}

func TestTimeStep(t *testing.T) {
	epoch := time.Unix(0, 0)
	if got := TimeStep(epoch, 30); got != 0 {
		t.Errorf("TimeStep(epoch, 30) = %d, want 0", got)
	}
	t90 := time.Unix(90, 0)
	if got := TimeStep(t90, 30); got != 3 {
		t.Errorf("TimeStep(90s, 30) = %d, want 3", got)
	}
}
