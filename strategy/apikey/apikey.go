// Package apikey implements the API-key authentication strategy.
//
// The library treats an API key as a long random secret bound to a single
// principal. The key is presented in clear text by the client (typically in
// an HTTP header) and verified by hashing the secret half with HMAC-SHA256
// and comparing it constant-time against the row stored in a KeyStore.
//
// Key format: <prefix>_<env>_<random28base32> e.g. "sk_live_AB12...XY".
//
//	prefix: caller-defined (e.g. "sk", "pk", "tok") — distinguishes key
//	        kinds at a glance.
//	env:    short environment marker (e.g. "live", "test"). Optional.
//	body:   28 bytes of crypto/rand → 45 base32 characters (lowercase).
//
// Only the prefix+env (and a key-id, if you want one) are stored in
// plaintext: the body is hashed. This means:
//
//   - Lookup is O(1): split the key, look up by prefix+env+key-id.
//   - Database leak alone does NOT compromise active keys (the attacker
//     cannot reverse HMAC-SHA256 without the pepper).
//   - Comparison is constant-time.
//
// The application supplies a KeyStore implementation (database, in-memory,
// Vault, …). The library never imports a database driver itself.
package apikey

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yurii-bondar/multipass"
)

const Name = "apikey"

// Record is one row in the KeyStore. The application persists this struct
// (or its fields) however it likes.
type Record struct {
	ID        string   // application-scoped key id (e.g. uuid)
	Prefix    string   // "sk_live"
	UserID    string   // principal subject
	HashHex   string   // hex(HMAC-SHA256(pepper, body))
	Scopes    []string // optional permissions
	CreatedAt time.Time
	ExpiresAt time.Time // zero == no expiry
	Revoked   bool
	Metadata  map[string]any
}

// KeyStore is the persistence port for API keys. The library never imports
// a database driver; the host application implements this interface using
// whatever store fits (Postgres, DynamoDB, Redis, …).
type KeyStore interface {
	// Save persists a freshly created record.
	Save(ctx context.Context, rec Record) error
	// FindByID returns the record by its key id (the public part embedded
	// in the credential). Should return store.ErrNotFound or a sentinel of
	// the implementation's choice when missing — the strategy translates
	// any error to ErrTokenInvalid externally.
	FindByID(ctx context.Context, id string) (*Record, error)
	// Revoke marks a key as revoked. Idempotent.
	Revoke(ctx context.Context, id string) error
	// RevokeAllForUser revokes every key of a user.
	RevokeAllForUser(ctx context.Context, userID string) error
}

// Strategy implements the API-key strategy.
type Strategy struct {
	store  KeyStore
	pepper []byte
	prefix string // "sk"
	env    string // "live" / "test"; may be empty
	clock  multipass.Clock
}

// Option configures the strategy.
type Option func(*Strategy)

// WithPepper sets the server-side HMAC key. Required: without it, a DB leak
// trivially yields all active API keys.
func WithPepper(p []byte) Option { return func(s *Strategy) { s.pepper = p } }

// WithPrefix sets the human-friendly key kind, e.g. "sk".
func WithPrefix(p string) Option { return func(s *Strategy) { s.prefix = p } }

// WithEnv sets the env marker, e.g. "live" or "test".
func WithEnv(e string) Option { return func(s *Strategy) { s.env = e } }

// WithClock overrides the clock (testing).
func WithClock(c multipass.Clock) Option { return func(s *Strategy) { s.clock = c } }

// New constructs the API-key strategy.
func New(st KeyStore, opts ...Option) (*Strategy, error) {
	if st == nil {
		return nil, errors.New("apikey: KeyStore is required")
	}
	s := &Strategy{store: st, clock: multipass.SystemClock(), prefix: "sk"}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.pepper) < 16 {
		return nil, errors.New("apikey: WithPepper requires at least 16 bytes")
	}
	return s, nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue creates a new key for the given principal. The plaintext key is
// returned in Credentials.Access; this is the ONLY moment the caller can see
// the full secret — the server only stores its hash.
//
// You can attach scopes via Principal.Extra["scopes"] []string and an
// optional explicit ExpiresAt via Principal.ExpiresAt.
func (s *Strategy) Issue(ctx context.Context, p multipass.Principal) (multipass.Credentials, error) {
	id, err := randomBase32(8) // 8 bytes -> 13 chars
	if err != nil {
		return multipass.Credentials{}, err
	}
	body, err := randomBase32(28) // 28 bytes -> 45 chars
	if err != nil {
		return multipass.Credentials{}, err
	}
	prefix := s.compoundPrefix()
	plain := fmt.Sprintf("%s_%s_%s", prefix, id, body)

	rec := Record{
		ID:        id,
		Prefix:    prefix,
		UserID:    p.UserID,
		HashHex:   s.hash(body),
		CreatedAt: s.clock.Now(),
		ExpiresAt: p.ExpiresAt,
		Metadata:  p.Extra,
	}
	if scopes, ok := getScopes(p.Extra); ok {
		rec.Scopes = scopes
	}
	if err := s.store.Save(ctx, rec); err != nil {
		return multipass.Credentials{}, fmt.Errorf("apikey: save: %w", err)
	}
	return multipass.Credentials{
		Access:       plain,
		TokenType:    "API-Key",
		AccessExpiry: rec.ExpiresAt,
		Subject:      p.UserID,
	}, nil
}

// Verify validates a presented key and returns the underlying Principal.
func (s *Strategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	prefix, id, body, ok := splitKey(raw)
	if !ok || prefix != s.compoundPrefix() {
		return nil, multipass.ErrTokenInvalid
	}
	rec, err := s.store.FindByID(ctx, id)
	if err != nil || rec == nil {
		return nil, multipass.ErrTokenInvalid
	}
	if rec.Revoked {
		return nil, multipass.ErrTokenRevoked
	}
	if !rec.ExpiresAt.IsZero() && s.clock.Now().After(rec.ExpiresAt) {
		return nil, multipass.ErrTokenExpired
	}
	if subtle.ConstantTimeCompare([]byte(rec.HashHex), []byte(s.hash(body))) != 1 {
		return nil, multipass.ErrTokenInvalid
	}
	p := &multipass.Principal{
		UserID:       rec.UserID,
		Extra:        rec.Metadata,
		StrategyName: Name,
		TokenID:      rec.ID,
		IssuedAt:     rec.CreatedAt,
		ExpiresAt:    rec.ExpiresAt,
	}
	if len(rec.Scopes) > 0 {
		if p.Extra == nil {
			p.Extra = make(map[string]any)
		}
		p.Extra["scopes"] = rec.Scopes
	}
	return p, nil
}

// Revoke marks the presented key as revoked. Idempotent.
func (s *Strategy) Revoke(ctx context.Context, raw string) error {
	_, id, _, ok := splitKey(raw)
	if !ok {
		return multipass.ErrTokenInvalid
	}
	return s.store.Revoke(ctx, id)
}

// RevokeAllForUser revokes every API key owned by the user.
func (s *Strategy) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.store.RevokeAllForUser(ctx, userID)
}

// ----- helpers -------------------------------------------------------------

func (s *Strategy) compoundPrefix() string {
	if s.env == "" {
		return s.prefix
	}
	return s.prefix + "_" + s.env
}

func (s *Strategy) hash(body string) string {
	mac := hmac.New(sha256.New, s.pepper)
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// splitKey parses "<prefix>_<id>_<body>" with a flexible <prefix> that may
// itself contain underscores (e.g. "sk_live_<id>_<body>").
func splitKey(raw string) (prefix, id, body string, ok bool) {
	parts := strings.Split(raw, "_")
	if len(parts) < 3 {
		return "", "", "", false
	}
	body = parts[len(parts)-1]
	id = parts[len(parts)-2]
	prefix = strings.Join(parts[:len(parts)-2], "_")
	if prefix == "" || id == "" || body == "" {
		return "", "", "", false
	}
	return prefix, id, body, true
}

// base32 lowercase, no padding — easy to type, URL-safe.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomBase32(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToLower(b32.EncodeToString(buf)), nil
}

func getScopes(extra map[string]any) ([]string, bool) {
	if extra == nil {
		return nil, false
	}
	v, ok := extra["scopes"]
	if !ok {
		return nil, false
	}
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.RevokeAllable = (*Strategy)(nil)
)
