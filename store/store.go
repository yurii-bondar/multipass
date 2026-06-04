// Package store defines the persistence ports the strategies depend on.
//
// The library is database- and cache-agnostic: it never imports a Redis
// driver, a SQL driver, or anything else with side-effects. Instead, every
// strategy that needs persistence accepts an interface from this package
// and the host application supplies the implementation (Redis, Postgres,
// DynamoDB, in-memory, …).
//
// The reference in-memory implementations live in store/memory and are
// suitable for tests, examples and single-process toy deployments — never
// for production with more than one replica.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by Store implementations when a key is missing.
// Callers must use errors.Is for comparison.
var ErrNotFound = errors.New("store: not found")

// SessionData is the payload kept under a session id. Implementations should
// treat this struct as opaque and persist it as a whole (e.g. JSON or
// gob-encoded). It is intentionally small.
type SessionData struct {
	UserID    string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time            // absolute timeout (hard cap)
	LastSeen  time.Time            // updated on Touch (idle timeout)
	Extra     map[string]any
}

// SessionStore persists opaque server-side sessions. ttl is the absolute
// remaining lifetime; implementations should use it both as a backing-store
// expiry hint (Redis EXPIRE) and as a return-time check.
type SessionStore interface {
	Save(ctx context.Context, sid string, data SessionData, ttl time.Duration) error
	Get(ctx context.Context, sid string) (*SessionData, error)
	Touch(ctx context.Context, sid string, ttl time.Duration) error
	Delete(ctx context.Context, sid string) error
	DeleteByUser(ctx context.Context, userID string) error
}

// Blacklist tracks revoked JWT/PASETO ids. The expiresAt parameter lets
// implementations prune entries automatically once the underlying token
// would have expired anyway.
type Blacklist interface {
	Add(ctx context.Context, jti string, expiresAt time.Time) error
	Has(ctx context.Context, jti string) (bool, error)
}

// RefreshRecord describes one refresh-token row inside a RefreshStore. Used
// only as a return value of internal helpers; production implementations may
// inline these fields.
type RefreshRecord struct {
	JTI       string
	UserID    string
	FamilyID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Used      bool
}

// RefreshStore implements refresh-token rotation with reuse detection.
//
// Workflow:
//
//   - On login, the JWT strategy calls Save once with the freshly issued
//     refresh token.
//   - On refresh, it calls RotateAndCheck atomically: the old jti is marked
//     used and the new one is inserted in the same transaction. If the old
//     jti was already marked used, the call returns reused=true; the
//     strategy then calls KillFamily to wipe every refresh in that family
//     (the user is logged out from every device).
//   - On explicit logout, Revoke removes the current refresh and (optionally)
//     blacklists its access counterpart.
//
// Implementations MUST make RotateAndCheck atomic with respect to concurrent
// callers (two parallel refresh requests with the same old jti must not
// both succeed).
type RefreshStore interface {
	Save(ctx context.Context, rec RefreshRecord) error

	RotateAndCheck(
		ctx context.Context,
		oldJTI string,
		newJTI string,
		newExpiresAt time.Time,
	) (rec RefreshRecord, reused bool, err error)

	Revoke(ctx context.Context, jti string) error
	KillFamily(ctx context.Context, familyID string) error
	KillUser(ctx context.Context, userID string) error
}

// OTPPayload is the struct stored under a one-time-code key.
type OTPPayload struct {
	UserID  string
	Email   string
	Purpose string // "login", "email-verify", "password-reset", ...
	Extra   map[string]any
}

// OTPStore persists single-use codes (magic links, numeric OTPs).
//
// Consume MUST be atomic delete-on-read: returning the payload AND removing
// the key in a single operation, so a code can never be redeemed twice.
// Implementations on top of Redis can use GETDEL (>=6.2) or a Lua script;
// SQL implementations should use a transaction with SELECT … FOR UPDATE.
type OTPStore interface {
	Save(ctx context.Context, code string, payload OTPPayload, ttl time.Duration) error
	Consume(ctx context.Context, code string) (*OTPPayload, error)
}
