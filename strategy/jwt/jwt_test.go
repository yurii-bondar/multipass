package jwt_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/jwt"
)

// ----- helpers -------------------------------------------------------------

func ed25519Key(t *testing.T) jwt.Key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{KID: "k1", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}
}

func rsaKey(t *testing.T) jwt.Key {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{KID: "rsa1", Alg: jwt.AlgRS256, Priv: priv, Pub: &priv.PublicKey}
}

func newStrategy(t *testing.T, opts ...jwt.Option) *jwt.Strategy {
	t.Helper()
	k := ed25519Key(t)
	all := append([]jwt.Option{
		jwt.WithIssuer("test"),
		jwt.WithAudience("api"),
		jwt.WithAccessTTL(time.Minute),
		jwt.WithRefreshTTL(time.Hour),
		jwt.WithBlacklist(memory.NewBlacklist()),
		jwt.WithRefreshStore(memory.NewRefreshStore()),
	}, opts...)
	s, err := jwt.New(jwt.StaticKeyProvider{K: k}, all...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ----- tests ---------------------------------------------------------------

func TestIssueAndVerify(t *testing.T) {
	s := newStrategy(t)
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Email: "a@b", Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if creds.Access == "" || creds.Refresh == "" {
		t.Fatal("missing tokens")
	}
	p, err := s.Verify(context.Background(), creds.Access)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "u1" || p.Email != "a@b" || len(p.Roles) != 1 {
		t.Errorf("principal: %+v", p)
	}
}

func TestVerify_RejectsRefreshTokenAsAccess(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), creds.Refresh); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	s := newStrategy(t, jwt.WithAccessTTL(time.Millisecond), jwt.WithLeeway(0))
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	time.Sleep(40 * time.Millisecond)
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	parts := strings.Split(creds.Access, ".")
	parts[2] = parts[2][:len(parts[2])-2] + "XX"
	if _, err := s.Verify(context.Background(), strings.Join(parts, ".")); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	s := newStrategy(t)
	// Build a "none" token by hand and try to verify.
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, jwtv5.RegisteredClaims{Subject: "u1"})
	raw, err := tok.SignedString(jwtv5.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), raw); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected alg=none to be rejected, got %v", err)
	}
}

func TestVerify_RejectsWrongAlgorithm(t *testing.T) {
	// Strategy expects EdDSA; sign with HS256 using arbitrary secret.
	s := newStrategy(t)
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, jwtv5.RegisteredClaims{Subject: "u1"})
	raw, _ := tok.SignedString([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if _, err := s.Verify(context.Background(), raw); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected wrong-alg rejection, got %v", err)
	}
}

func TestRevoke_Blacklists(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err := s.Revoke(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestRevoke_AcceptsExpiredToken(t *testing.T) {
	s := newStrategy(t, jwt.WithAccessTTL(time.Millisecond), jwt.WithLeeway(0))
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	time.Sleep(40 * time.Millisecond)
	if err := s.Revoke(context.Background(), creds.Access); err != nil {
		t.Fatalf("Revoke should accept expired tokens: %v", err)
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Email: "a@b"})
	new1, err := s.Refresh(context.Background(), creds.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	if new1.Access == "" || new1.Refresh == "" {
		t.Fatal("rotated tokens missing")
	}
	if new1.Access == creds.Access || new1.Refresh == creds.Refresh {
		t.Fatal("rotation must change both tokens")
	}
	// New access verifies.
	if _, err := s.Verify(context.Background(), new1.Access); err != nil {
		t.Fatalf("new access does not verify: %v", err)
	}
}

func TestRefresh_ReuseKillsFamily(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	// First rotate succeeds.
	r1, err := s.Refresh(context.Background(), creds.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying the original refresh must trip reuse detection.
	if _, err := s.Refresh(context.Background(), creds.Refresh); !errors.Is(err, multipass.ErrReuseDetected) {
		t.Fatalf("expected ErrReuseDetected, got %v", err)
	}
	// Family is killed: the legitimate r1.Refresh should now also be useless.
	if _, err := s.Refresh(context.Background(), r1.Refresh); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked after family kill, got %v", err)
	}
}

func TestRefresh_RejectsAccessToken(t *testing.T) {
	s := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Refresh(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestRefresh_NoStoreReturnsUnsupported(t *testing.T) {
	k := ed25519Key(t)
	s, err := jwt.New(jwt.StaticKeyProvider{K: k}, jwt.WithIssuer("t"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background(), "anything"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestRevokeAllForUser(t *testing.T) {
	rs := memory.NewRefreshStore()
	s := newStrategy(t, jwt.WithRefreshStore(rs))
	creds1, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	creds2, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err := s.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background(), creds1.Refresh); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("creds1 should be revoked: %v", err)
	}
	if _, err := s.Refresh(context.Background(), creds2.Refresh); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("creds2 should be revoked: %v", err)
	}
}

func TestRSA256Works(t *testing.T) {
	k := rsaKey(t)
	s, err := jwt.New(jwt.StaticKeyProvider{K: k},
		jwt.WithAlgorithm(jwt.AlgRS256),
		jwt.WithIssuer("t"),
		jwt.WithBlacklist(memory.NewBlacklist()),
		jwt.WithRefreshStore(memory.NewRefreshStore()),
	)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); err != nil {
		t.Fatalf("RSA verify failed: %v", err)
	}
}

func TestKeyRotation_VerifyOldSignButNew(t *testing.T) {
	k1 := ed25519Key(t)
	k1.KID = "old"
	k2 := ed25519Key(t)
	k2.KID = "new"
	mp := jwt.NewMultiKeyProvider(k1)
	mp.AddKey(k2)
	s, err := jwt.New(mp, jwt.WithIssuer("t"))
	if err != nil {
		t.Fatal(err)
	}
	// Issue with k1 (current).
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
	// Promote k2.
	if err := mp.SetCurrent("new"); err != nil {
		t.Fatal(err)
	}
	// Old token (kid=old) must still verify.
	if _, err := s.Verify(context.Background(), creds.Access); err != nil {
		t.Fatalf("old kid token should still verify: %v", err)
	}
	// New token uses kid=new.
	creds2, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), creds2.Access); err != nil {
		t.Fatalf("new kid token should verify: %v", err)
	}
	// Removing k1 invalidates old tokens.
	mp.RemoveKey("old")
	if _, err := s.Verify(context.Background(), creds.Access); err == nil {
		t.Fatalf("old token should fail after key removal")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	k := ed25519Key(t)
	signer, _ := jwt.New(jwt.StaticKeyProvider{K: k}, jwt.WithIssuer("issuer-A"))
	verifier, _ := jwt.New(jwt.StaticKeyProvider{K: k}, jwt.WithIssuer("issuer-B"))
	creds, _ := signer.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := verifier.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected wrong issuer to fail, got %v", err)
	}
}
