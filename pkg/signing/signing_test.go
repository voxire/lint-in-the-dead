package signing_test

import (
	"testing"

	"github.com/voxire/lint-in-the-dead/pkg/signing"
)

func TestSign_Deterministic(t *testing.T) {
	a := signing.Sign("secret", "payload")
	b := signing.Sign("secret", "payload")
	if a != b {
		t.Errorf("Sign is not deterministic: %q != %q", a, b)
	}
}

func TestSign_DifferentSecrets(t *testing.T) {
	a := signing.Sign("secret1", "payload")
	b := signing.Sign("secret2", "payload")
	if a == b {
		t.Error("different secrets produced identical signatures")
	}
}

func TestSign_DifferentPayloads(t *testing.T) {
	a := signing.Sign("secret", "payload1")
	b := signing.Sign("secret", "payload2")
	if a == b {
		t.Error("different payloads produced identical signatures")
	}
}

func TestVerify_Valid(t *testing.T) {
	sig := signing.Sign("mysecret", "the data")
	if !signing.Verify("mysecret", "the data", sig) {
		t.Error("Verify returned false for a valid signature")
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	sig := signing.Sign("correct", "data")
	if signing.Verify("wrong", "data", sig) {
		t.Error("Verify returned true with wrong secret")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	sig := signing.Sign("secret", "original")
	if signing.Verify("secret", "tampered", sig) {
		t.Error("Verify returned true for tampered payload")
	}
}

func TestVerify_EmptySignature(t *testing.T) {
	if signing.Verify("secret", "data", "") {
		t.Error("Verify returned true for empty signature")
	}
}

func TestSignGitHub_Format(t *testing.T) {
	sig := signing.SignGitHub("secret", []byte("body"))
	if len(sig) < 7 || sig[:7] != "sha256=" {
		t.Errorf("SignGitHub signature missing sha256= prefix: %q", sig)
	}
}

func TestVerifyGitHub_Valid(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	header := signing.SignGitHub("webhook-secret", body)
	if !signing.VerifyGitHub("webhook-secret", body, header) {
		t.Error("VerifyGitHub returned false for valid webhook signature")
	}
}

func TestVerifyGitHub_InvalidSecret(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	header := signing.SignGitHub("correct-secret", body)
	if signing.VerifyGitHub("wrong-secret", body, header) {
		t.Error("VerifyGitHub returned true with wrong secret")
	}
}

func TestVerifyGitHub_TamperedBody(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	header := signing.SignGitHub("secret", body)
	tampered := []byte(`{"action":"closed"}`)
	if signing.VerifyGitHub("secret", tampered, header) {
		t.Error("VerifyGitHub returned true for tampered body")
	}
}
