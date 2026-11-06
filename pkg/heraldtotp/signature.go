package heraldtotp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SignatureVersion is the operation-bound TOTP request-authentication protocol.
const SignatureVersion = "v2"

// MaxAuthIdentifierBytes bounds each service name and HMAC key ID on the wire.
const MaxAuthIdentifierBytes = 128

// RequestSignature contains the fields authenticated by a v2 request.
type RequestSignature struct {
	Method, Path, Query, KeyID, Timestamp, Service, Nonce string
	Body                                                  []byte
}

// SignV2 authenticates length-framed fields, including the escaped request target.
func SignV2(secret string, in RequestSignature) string {
	bodyHash := sha256.Sum256(in.Body)
	var canonical strings.Builder
	for _, field := range []string{SignatureVersion, in.Method, in.Path, in.Query, in.KeyID, in.Timestamp, in.Service, in.Nonce, hex.EncodeToString(bodyHash[:])} {
		canonical.WriteString(strconv.Itoa(len(field)))
		canonical.WriteByte('\n')
		canonical.WriteString(field)
		canonical.WriteByte('\n')
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignRequest adds operation-bound headers with a cryptographically random nonce.
// Callers must not send the request if signing fails.
func SignRequest(req *http.Request, body []byte, secret, service, keyID string) error {
	return signRequest(req, body, secret, service, keyID, rand.Reader, time.Now())
}

func signRequest(req *http.Request, body []byte, secret, service, keyID string, reader io.Reader, now time.Time) error {
	if req == nil || req.URL == nil || secret == "" || service == "" {
		return errors.New("TOTP request signing requires a URL, service, and secret")
	}
	if len(service) > MaxAuthIdentifierBytes || len(keyID) > MaxAuthIdentifierBytes {
		return errors.New("TOTP service and key ID must not exceed 128 bytes")
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return errors.New("generate TOTP authentication nonce")
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	nonceHex := hex.EncodeToString(nonce)
	signature := SignV2(secret, RequestSignature{Method: req.Method, Path: req.URL.EscapedPath(), Query: req.URL.RawQuery, KeyID: keyID, Timestamp: ts, Service: service, Nonce: nonceHex, Body: body})
	req.Header.Set("X-Signature-Version", SignatureVersion)
	req.Header.Set("X-Signature", signature)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Service", service)
	req.Header.Set("X-Nonce", nonceHex)
	if keyID != "" {
		req.Header.Set("X-Key-Id", keyID)
	} else {
		req.Header.Del("X-Key-Id")
	}
	return nil
}
