package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// ErrKeySize is returned when the configured AES-256 key is not exactly 32 bytes.
var ErrKeySize = errors.New("encryption key must be exactly 32 bytes for AES-256")

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

// KeyBytes returns a validated 32-byte AES-256 key. It deliberately rejects
// shorter and longer values instead of silently padding or truncating them.
func KeyBytes(key string) ([]byte, error) {
	b := []byte(key)
	if len(b) != 32 {
		return nil, ErrKeySize
	}
	return b, nil
}
