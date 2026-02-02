package secret

import (
	"bytes"
	"testing"
)

func TestKeyBytes(t *testing.T) {
	// 0 length -> ErrKeySize
	_, err := KeyBytes("")
	if err != ErrKeySize {
		t.Errorf("KeyBytes(\"\") err = %v, want ErrKeySize", err)
	}

	// 16, 24, 32 bytes -> same slice
	for _, n := range []int{16, 24, 32} {
		key := string(bytes.Repeat([]byte("x"), n))
		b, err := KeyBytes(key)
		if err != nil {
			t.Errorf("KeyBytes(%d bytes): %v", n, err)
		}
		if len(b) != n {
			t.Errorf("KeyBytes(%d bytes) len = %d", n, len(b))
		}
	}

	// > 32 -> truncated to 32
	long := string(bytes.Repeat([]byte("a"), 40))
	b, err := KeyBytes(long)
	if err != nil {
		t.Fatalf("KeyBytes(40): %v", err)
	}
	if len(b) != 32 {
		t.Errorf("KeyBytes(40) len = %d, want 32", len(b))
	}

	// 10 bytes -> zero-padded to 32
	short := "1234567890"
	b, err = KeyBytes(short)
	if err != nil {
		t.Fatalf("KeyBytes(10): %v", err)
	}
	if len(b) != 32 {
		t.Errorf("KeyBytes(10) len = %d, want 32", len(b))
	}
	padded := make([]byte, 32)
	copy(padded, short)
	if !bytes.Equal(b, padded) {
		t.Error("KeyBytes(10) should be zero-padded to 32")
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
	// key length 1 is not 16/24/32, KeyBytes pads to 32 - so Encrypt gets 32 bytes
	// Actually KeyBytes("x") returns 32-byte padded. So Encrypt will work.
	// To get aes.NewCipher to fail we need key not 16/24/32. But KeyBytes always returns 16,24,32 or 32 padded.
	// So we can't easily get aes.NewCipher to fail from our API. Skip that.
	// Test Decrypt with wrong key (wrong plaintext after open)
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
