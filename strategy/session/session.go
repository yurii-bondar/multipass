// Package session implements opaque server-side sessions.
//
// A session id is a 32-byte random string (base64url) that carries no claims
// at all — every piece of state is kept server-side in a SessionStore. That
// means revocation is just a delete, and there is no risk of a forged token:
// only ids that the server itself produced will verify.
//
// Two timeouts are enforced:
//
//   - Absolute timeout (default 24 h): a hard cap; once it passes the
//     session is dead even if the user has been continuously active.
//   - Idle timeout (default 30 min): rolling. Each successful Verify can
//     extend the session via Touch, so an active user is not kicked out
//     mid-flow. Disabled by default; enable with WithIdleTimeout.
//
// Session fixation is mitigated by always issuing a fresh SID on Issue: any
// pre-existing SID for the same user can be (optionally) revoked via
// WithRevokeOldOnIssue.
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

const Name = "session"

// Strategy implements opaque server-side sessions.
type Strategy struct {
	store               store.SessionStore
	clock               multipass.Clock
	idgen               multipass.IDGen
	absoluteTTL         time.Duration
	idleTTL             time.Duration // 0 disables rolling extension
	revokeOldOnIssue    bool
}

// Option configures the session strategy.
type Option func(*Strategy)

// WithAbsoluteTTL is the hard cap on session lifetime. Default 24 h.
func WithAbsoluteTTL(d time.Duration) Option { return func(s *Strategy) { s.absoluteTTL = d } }

// WithIdleTimeout enables rolling extension on every successful Verify.
// The session expires if no Verify happens within d. Pass 0 to disable
// rolling and rely solely on the absolute timeout.
func WithIdleTimeout(d time.Duration) Option { return func(s *Strategy) { s.idleTTL = d } }

// WithClock overrides the clock (testing).
func WithClock(c multipass.Clock) Option { return func(s *Strategy) { s.clock = c } }

// WithIDGen overrides the SID generator. Default produces 32-byte ids.
func WithIDGen(g multipass.IDGen) Option { return func(s *Strategy) { s.idgen = g } }

// WithRevokeOldOnIssue, when true, calls SessionStore.DeleteByUser at
// Issue-time so a user has at most one active session at a time.
//
// Default is false: most apps want concurrent sessions across devices.
func WithRevokeOldOnIssue(b bool) Option { return func(s *Strategy) { s.revokeOldOnIssue = b } }

// New constructs a session strategy on top of the given SessionStore.
func New(st store.SessionStore, opts ...Option) (*Strategy, error) {
	if st == nil {
		return nil, errors.New("session: SessionStore is required")
	}
	s := &Strategy{
		store:       st,
		clock:       multipass.SystemClock(),
		idgen:       multipass.DefaultIDGen(),
		absoluteTTL: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue creates a fresh session and returns its SID as the Access token.
// Refresh is unused for sessions.
func (s *Strategy) Issue(ctx context.Context, p multipass.Principal) (multipass.Credentials, error) {
	if s.revokeOldOnIssue && p.UserID != "" {
		if err := s.store.DeleteByUser(ctx, p.UserID); err != nil {
			return multipass.Credentials{}, fmt.Errorf("session: revoke old: %w", err)
		}
	}

	sid, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("session: gen sid: %w", err)
	}
	now := s.clock.Now()
	abs := now.Add(s.absoluteTTL)

	data := store.SessionData{
		UserID:    p.UserID,
		Roles:     p.Roles,
		IssuedAt:  now,
		ExpiresAt: abs,
		LastSeen:  now,
		Extra:     p.Extra,
	}
	if err := s.store.Save(ctx, sid, data, s.absoluteTTL); err != nil {
		return multipass.Credentials{}, fmt.Errorf("session: save: %w", err)
	}
	return multipass.Credentials{
		Access:       sid,
		TokenType:    "Session",
		AccessExpiry: abs,
		Subject:      p.UserID,
	}, nil
}

// Verify looks up the session and, if alive, returns a Principal. When idle
// timeout is enabled it also calls Touch to refresh LastSeen.
func (s *Strategy) Verify(ctx context.Context, sid string) (*multipass.Principal, error) {
	data, err := s.store.Get(ctx, sid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, multipass.ErrTokenInvalid
		}
		return nil, fmt.Errorf("session: get: %w", err)
	}
	now := s.clock.Now()
	if !data.ExpiresAt.IsZero() && now.After(data.ExpiresAt) {
		_ = s.store.Delete(ctx, sid)
		return nil, multipass.ErrTokenExpired
	}
	if s.idleTTL > 0 && !data.LastSeen.IsZero() && now.Sub(data.LastSeen) > s.idleTTL {
		_ = s.store.Delete(ctx, sid)
		return nil, multipass.ErrTokenExpired
	}
	if s.idleTTL > 0 {
		// Bump LastSeen and extend the backing-store TTL by the smaller of
		// the remaining absolute lifetime and the idle window.
		remaining := data.ExpiresAt.Sub(now)
		ext := s.idleTTL
		if remaining > 0 && remaining < ext {
			ext = remaining
		}
		_ = s.store.Touch(ctx, sid, ext)
	}
	return &multipass.Principal{
		UserID:       data.UserID,
		Roles:        data.Roles,
		Extra:        data.Extra,
		StrategyName: Name,
		TokenID:      sid,
		IssuedAt:     data.IssuedAt,
		ExpiresAt:    data.ExpiresAt,
	}, nil
}

// Revoke deletes the session.
func (s *Strategy) Revoke(ctx context.Context, sid string) error {
	return s.store.Delete(ctx, sid)
}

// RevokeAllForUser deletes every session that belongs to userID.
func (s *Strategy) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.store.DeleteByUser(ctx, userID)
}

var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.RevokeAllable = (*Strategy)(nil)
)
