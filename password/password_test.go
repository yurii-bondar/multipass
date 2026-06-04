package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// fastParams keeps tests under a few milliseconds.
func fastParams() Argon2Params {
	return Argon2Params{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestHashAndVerify_RoundTrip(t *testing.T) {
	h := NewHasher(WithArgon2Params(fastParams()))
	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("expected argon2id prefix, got %q", encoded[:20])
	}
	rehash, err := h.Verify(encoded, "correct horse battery staple")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rehash {
		t.Errorf("unexpected NeedsRehash=true on fresh hash")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	h := NewHasher(WithArgon2Params(fastParams()))
	encoded, _ := h.Hash("hunter2")
	_, err := h.Verify(encoded, "wrong")
	if !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("expected ErrPasswordMismatch, got %v", err)
	}
}

func TestVerify_WithPepper(t *testing.T) {
	h := NewHasher(WithArgon2Params(fastParams()), WithPepper([]byte("server-secret-pepper")))
	encoded, _ := h.Hash("p4ssw0rd")
	if _, err := h.Verify(encoded, "p4ssw0rd"); err != nil {
		t.Fatalf("verify with same pepper failed: %v", err)
	}
	other := NewHasher(WithArgon2Params(fastParams()), WithPepper([]byte("DIFFERENT-pepper")))
	if _, err := other.Verify(encoded, "p4ssw0rd"); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("expected mismatch under different pepper, got %v", err)
	}
}

func TestVerify_BcryptLegacy(t *testing.T) {
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte("legacy"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("seed bcrypt: %v", err)
	}
	h := NewHasher(WithArgon2Params(fastParams()))
	rehash, err := h.Verify(string(bcryptHash), "legacy")
	if err != nil {
		t.Fatalf("Verify legacy bcrypt: %v", err)
	}
	if !rehash {
		t.Errorf("legacy bcrypt should signal NeedsRehash")
	}
}

func TestVerify_NeedsRehashOnWeakerParams(t *testing.T) {
	weak := NewHasher(WithArgon2Params(fastParams()))
	encoded, _ := weak.Hash("x")
	strong := NewHasher(WithArgon2Params(Argon2Params{
		Memory: 16 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32,
	}))
	rehash, err := strong.Verify(encoded, "x")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rehash {
		t.Errorf("expected NeedsRehash=true with stronger params")
	}
}

func TestVerify_MalformedHash(t *testing.T) {
	h := NewHasher(WithArgon2Params(fastParams()))
	if _, err := h.Verify("definitely not a hash", "x"); err == nil {
		t.Fatalf("expected error for malformed input")
	}
}

func TestFakeVerify_DoesNotPanic(t *testing.T) {
	h := NewHasher(WithArgon2Params(fastParams()))
	h.FakeVerify("anything")
}
