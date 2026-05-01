package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Sign produces a hex-encoded HMAC-SHA256 of data using secret.
func Sign(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks whether sig matches Sign(secret, data).
func Verify(secret, data, sig string) bool {
	expected := Sign(secret, data)
	return hmac.Equal([]byte(expected), []byte(sig))
}

// SignGitHub verifies a GitHub webhook signature (X-Hub-Signature-256 header).
func SignGitHub(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return fmt.Sprintf("sha256=%s", hex.EncodeToString(mac.Sum(nil)))
}

// VerifyGitHub checks the X-Hub-Signature-256 header value.
func VerifyGitHub(secret string, body []byte, header string) bool {
	expected := SignGitHub(secret, body)
	return hmac.Equal([]byte(expected), []byte(header))
}
