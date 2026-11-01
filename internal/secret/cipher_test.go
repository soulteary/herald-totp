package secret

import (
	"bytes"
	"crypto/fips140"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestKeyBytes(t *testing.T) {
	for _, n := range []int{0, 10, 16, 24, 31, 33, 40} {
		key := string(bytes.Repeat([]byte("x"), n))
		if _, err := KeyBytes(key); err != ErrKeySize {
			t.Errorf("KeyBytes(%d bytes) error = %v, want ErrKeySize", n, err)
		}
	}

	key := string(bytes.Repeat([]byte("x"), 32))
	b, err := KeyBytes(key)
	if err != nil {
		t.Fatalf("KeyBytes(32): %v", err)
	}
	if string(b) != key {
		t.Errorf("KeyBytes(32) = %q, want original key", string(b))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)

	// empty plaintext
	enc, err := Encrypt(key, "")
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	if enc != "" {
		t.Errorf("Encrypt empty = %q, want \"\"", enc)
	}
	dec, err := Decrypt(key, "")
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if dec != "" {
		t.Errorf("Decrypt empty = %q, want \"\"", dec)
	}

	// roundtrip
	plain := "my-secret-base32-key"
	enc, err = Encrypt(key, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == "" || enc == plain {
		t.Error("Encrypt should return non-empty encoded ciphertext")
	}
	dec, err = Decrypt(key, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != plain {
		t.Errorf("Decrypt = %q, want %q", dec, plain)
	}
}

func TestDecryptInvalid(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)

	// invalid base64
	_, err := Decrypt(key, "!!!not-base64!!!")
	if err == nil {
		t.Error("Decrypt invalid base64 should error")
	}

	// too short (no nonce)
	_, err = Decrypt(key, "YQ==") // "a" in base64
	if err == nil {
		t.Error("Decrypt too short should error")
	}
}

func TestEncryptInvalidKey(t *testing.T) {
	if _, err := Encrypt([]byte("short"), "secret"); err == nil {
		t.Error("Encrypt with invalid AES key should error")
	}
	if _, err := Decrypt([]byte("short"), "YQ=="); err == nil {
		t.Error("Decrypt with invalid AES key should error")
	}

	// Decrypting with a different valid key must fail authentication.
	keyGood := bytes.Repeat([]byte("a"), 32)
	keyBad := bytes.Repeat([]byte("b"), 32)
	enc, err := Encrypt(keyGood, "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = Decrypt(keyBad, enc)
	if err == nil {
		t.Error("Decrypt with wrong key should error")
	}
}

func TestEncryptRejectsUnavailableNonce(t *testing.T) {
	old := rand.Reader
	rand.Reader = bytes.NewReader(nil)
	t.Cleanup(func() { rand.Reader = old })
	encoded, err := Encrypt([]byte("0123456789abcdef0123456789abcdef"), "test-secret")
	if err == nil || encoded != "" {
		t.Fatalf("unavailable nonce produced ciphertext=%q error=%v", encoded, err)
	}
}

func TestStrictFIPSPolicyRejectsExplicitNonceEncryption(t *testing.T) {
	if os.Getenv("HERALD_TEST_FIPS_ONLY") == "1" {
		if !fips140.Enforced() {
			t.Fatal("strict crypto policy was not enabled")
		}
		key := bytes.Repeat([]byte("k"), 32)
		encrypted, err := Encrypt(key, "policy-test-plaintext")
		if encrypted != "" || err == nil || !strings.Contains(err.Error(), "FIPS 140-only") {
			t.Fatalf("encryption did not preserve policy rejection: result=%q error=%v", encrypted, err)
		}
		decoded, err := Decrypt(key, base64.StdEncoding.EncodeToString(make([]byte, 28)))
		if decoded != "" || err == nil || !strings.Contains(err.Error(), "FIPS 140-only") {
			t.Fatalf("decryption did not preserve policy rejection: result=%q error=%v", decoded, err)
		}
		return
	}
	args := []string{"-test.run=^TestStrictFIPSPolicyRejectsExplicitNonceEncryption$"}
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+coverage.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "HERALD_TEST_FIPS_ONLY=1", "GODEBUG=fips140=only")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strict crypto-policy subprocess: %v\n%s", err, output)
	}
}
