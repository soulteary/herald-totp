package handler

import (
	"crypto/rand"
	encoding "encoding/base64"
)

const idPrefixEnroll = "e_"
const idPrefixChallenge = "c_"
const randomIDLen = 12 // 12 bytes -> 16 chars base64url

// NewEnrollID returns a new enrollment ID (e_xxxx).
func NewEnrollID() (string, error) {
	b := make([]byte, randomIDLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return idPrefixEnroll + encoding.URLEncoding.EncodeToString(b)[:16], nil
}

// NewChallengeID returns a new challenge ID (c_xxxx) for optional replay tracking.
func NewChallengeID() (string, error) {
	b := make([]byte, randomIDLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return idPrefixChallenge + encoding.URLEncoding.EncodeToString(b)[:16], nil
}
