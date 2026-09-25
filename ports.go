package multipass

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"
)

// User is the canonical user record returned by UserRepository. The hash is
// kept server-side; the password itself never leaves the local strategy.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Roles        []string
	Disabled     bool
	FailedLogins int
	LockedUntil  time.Time
	PasswordVer  int    // bumped on password change; can be embedded in tokens to invalidate all old tokens
	MFASecret    string // optional: TOTP secret for 2FA
	Metadata     map[string]any
}

// UserRepository is the database-agnostic contract a host application must
// implement. The library never imports a SQL driver, an ORM, or any other
// persistence dependency.
//
// Implementations MUST return ErrUserNotFound (not nil + nil pointer) when a
// user does not exist; this lets the strategy layer perform constant-time
// fake hashing to defend against account enumeration.
type UserRepository interface {
	GetByID(ctx context.Context, id string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Create(ctx context.Context, u *User) error
	UpdatePasswordHash(ctx context.Context, id, hash string, version int) error
	IncrementFailedLogin(ctx context.Context, id string, lockUntil time.Time) (int, error)
	ResetFailedLogin(ctx context.Context, id string) error
}

// Clock abstracts time.Now to make TTL-based logic testable.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock returns a Clock backed by time.Now. Default for the library.
func SystemClock() Clock { return systemClock{} }

// IDGen produces unguessable identifiers. The default implementation uses
// crypto/rand and base64.RawURLEncoding (32 bytes -> 43 char string).
type IDGen interface {
	NewID() (string, error)
}

type defaultIDGen struct {
	bytes int
}

func (g defaultIDGen) NewID() (string, error) {
	n := g.bytes
	if n <= 0 {
		n = 32
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DefaultIDGen returns a 256-bit (32-byte) random-id generator.
func DefaultIDGen() IDGen { return defaultIDGen{bytes: 32} }

// NewIDGen returns an IDGen that produces ids of the given byte length.
func NewIDGen(bytes int) IDGen { return defaultIDGen{bytes: bytes} }
