package apikey_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/strategy/apikey"
)

// ----- in-memory KeyStore --------------------------------------------------

type memStore struct {
	mu   sync.Mutex
	byID map[string]*apikey.Record
}

func newMemStore() *memStore { return &memStore{byID: map[string]*apikey.Record{}} }

func (m *memStore) Save(_ context.Context, rec apikey.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := rec
	m.byID[rec.ID] = &cp
	return nil
}
func (m *memStore) FindByID(_ context.Context, id string) (*apikey.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *r
	return &cp, nil
}
func (m *memStore) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.byID[id]; ok {
		r.Revoked = true
	}
	return nil
}
func (m *memStore) RevokeAllForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.byID {
		if r.UserID == userID {
			r.Revoked = true
		}
	}
	return nil
}

// ----- helpers -------------------------------------------------------------

func newStrategy(t *testing.T) (*apikey.Strategy, *memStore) {
	t.Helper()
	st := newMemStore()
	s, err := apikey.New(st,
		apikey.WithPepper([]byte("0123456789abcdef0123456789abcdef")),
		apikey.WithPrefix("sk"),
		apikey.WithEnv("test"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

// ----- tests ---------------------------------------------------------------

func TestIssueFormat(t *testing.T) {
	s, _ := newStrategy(t)
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(creds.Access, "sk_test_") {
		t.Errorf("unexpected prefix: %q", creds.Access)
	}
	if creds.TokenType != "API-Key" {
		t.Errorf("token type: %q", creds.TokenType)
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	s, _ := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{
		UserID: "u1",
		Extra:  map[string]any{"scopes": []string{"read", "write"}},
	})
	p, err := s.Verify(context.Background(), creds.Access)
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "u1" {
		t.Errorf("subject: %q", p.UserID)
	}
	scopes, _ := p.Extra["scopes"].([]string)
	if len(scopes) != 2 {
		t.Errorf("scopes: %v", scopes)
	}
}

func TestVerify_Tampered(t *testing.T) {
	s, _ := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	tampered := creds.Access[:len(creds.Access)-2] + "xx"
	if _, err := s.Verify(context.Background(), tampered); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerify_WrongPrefix(t *testing.T) {
	s, _ := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	other := "pk_test_" + strings.SplitN(creds.Access, "_", 3)[2]
	if _, err := s.Verify(context.Background(), other); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected wrong-prefix rejection, got %v", err)
	}
}

func TestVerify_Revoked(t *testing.T) {
	s, _ := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err := s.Revoke(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	s, _ := newStrategy(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{
		UserID:    "u1",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRevokeAllForUser(t *testing.T) {
	s, _ := newStrategy(t)
	a, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	b, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	c, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u2"})
	if err := s.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{a.Access, b.Access} {
		if _, err := s.Verify(context.Background(), k); !errors.Is(err, multipass.ErrTokenRevoked) {
			t.Errorf("expected revoked, got %v", err)
		}
	}
	if _, err := s.Verify(context.Background(), c.Access); err != nil {
		t.Errorf("u2 key should remain: %v", err)
	}
}

func BenchmarkVerify(b *testing.B) {
	s, _ := newStrategy(&testing.T{})
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Verify(context.Background(), creds.Access); err != nil {
			b.Fatal(err)
		}
	}
}
