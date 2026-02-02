package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// ErrKeySize is returned when the encryption key is not 16, 24, or 32 bytes.
var ErrKeySize = errors.New("encryption key must be 16, 24, or 32 bytes for AES")

// Encrypt encrypts plaintext with AES-GCM using the given key. Key must be 16, 24, or 32 bytes.
// Returns base64-encoded nonce+ciphertext.
func Encrypt(key []byte, plaintext string) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded nonce+ciphertext with AES-GCM.
func Decrypt(key []byte, encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// KeyBytes returns the key as bytes, truncating or zero-padding to 32 bytes for AES-256.
// If key is shorter than 32 bytes, it is zero-padded (not recommended for production).
func KeyBytes(key string) ([]byte, error) {
	b := []byte(key)
	switch len(b) {
	case 16, 24, 32:
		return b, nil
	case 0:
		return nil, ErrKeySize
	default:
		if len(b) > 32 {
			return b[:32], nil
		}
		// Pad to 32
		padded := make([]byte, 32)
		copy(padded, b)
		return padded, nil
	}
}
