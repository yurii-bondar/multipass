// Package local implements the email+password ("local") strategy.
//
// The strategy implements multipass.Authenticator (verifies a credential pair
// against the user repository) but is intentionally NOT a token issuer:
// after a successful Authenticate the application chooses which token-bearing
// strategy (jwt, paseto, session, …) issues the actual credential.
//
// Defenses built in:
//
//   - Argon2id by default, bcrypt understood for legacy.
//   - Constant-time compare and uniform timing for "user not found" via
//     password.FakeVerify.
//   - Account lockout after a configurable number of consecutive failed
//     attempts; the user repository is the source of truth for the counter
//     so it survives process restarts.
//   - Optional opportunistic re-hash on successful login when the stored
//     hash is bcrypt or uses weaker argon2id parameters than the active
//     hasher.
package local

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/password"
)

const Name = "local"

// Strategy implements the local password verification strategy.
type Strategy struct {
	users           multipass.UserRepository
	hasher          *password.Hasher
	clock           multipass.Clock
	maxFailedLogins int
	lockoutFor      time.Duration
	rehashOnLogin   bool
}

// Option configures the local strategy.
type Option func(*Strategy)

// WithMaxFailedLogins sets the threshold (default 10). Zero disables lockout.
func WithMaxFailedLogins(n int) Option { return func(s *Strategy) { s.maxFailedLogins = n } }

// WithLockoutDuration sets the lockout window (default 15 min).
func WithLockoutDuration(d time.Duration) Option { return func(s *Strategy) { s.lockoutFor = d } }

// WithClock overrides the clock (testing).
func WithClock(c multipass.Clock) Option { return func(s *Strategy) { s.clock = c } }

// WithRehashOnLogin enables (true by default) opportunistic password re-hashing
// after a successful login when the stored hash is weaker than the current
// hasher's parameters.
func WithRehashOnLogin(enabled bool) Option { return func(s *Strategy) { s.rehashOnLogin = enabled } }

// New constructs a local strategy.
func New(users multipass.UserRepository, hasher *password.Hasher, opts ...Option) *Strategy {
	s := &Strategy{
		users:           users,
		hasher:          hasher,
		clock:           multipass.SystemClock(),
		maxFailedLogins: 10,
		lockoutFor:      15 * time.Minute,
		rehashOnLogin:   true,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue is not supported on the local strategy: it is a verifier, not an
// issuer. Callers should pass the resulting Principal to a token strategy.
func (s *Strategy) Issue(_ context.Context, _ multipass.Principal) (multipass.Credentials, error) {
	return multipass.Credentials{}, fmt.Errorf("%w: local.Issue", multipass.ErrUnsupportedOperation)
}

// Verify is not meaningful for local: a "credential" here is a password,
// not a serialisable token. It is provided to satisfy multipass.Strategy and
// always returns ErrUnsupportedOperation.
func (s *Strategy) Verify(_ context.Context, _ string) (*multipass.Principal, error) {
	return nil, fmt.Errorf("%w: local.Verify", multipass.ErrUnsupportedOperation)
}

// Revoke is a no-op for local (passwords are not revocable artefacts).
func (s *Strategy) Revoke(_ context.Context, _ string) error { return nil }

// Authenticate validates an email+password pair and returns a Principal on
// success. Implements multipass.Authenticator.
//
// The function intentionally returns multipass.ErrInvalidCredentials for both
// "user does not exist" and "wrong password" so an attacker cannot enumerate
// accounts. The timing of those two paths is also kept similar by running
// password.FakeVerify on the not-found path.
func (s *Strategy) Authenticate(ctx context.Context, identifier, secret string) (*multipass.Principal, error) {
	email := strings.ToLower(strings.TrimSpace(identifier))
	if email == "" || secret == "" {
		s.hasher.FakeVerify(secret)
		return nil, multipass.ErrInvalidCredentials
	}

	user, err := s.users.GetByEmail(ctx, email)
	switch {
	case errors.Is(err, multipass.ErrUserNotFound):
		s.hasher.FakeVerify(secret)
		return nil, multipass.ErrInvalidCredentials
	case err != nil:
		// Real I/O error: surface but do not leak which user.
		s.hasher.FakeVerify(secret)
		return nil, fmt.Errorf("local: lookup user: %w", err)
	}

	if user.Disabled {
		s.hasher.FakeVerify(secret)
		return nil, multipass.ErrInvalidCredentials
	}
	if !user.LockedUntil.IsZero() && s.clock.Now().Before(user.LockedUntil) {
		s.hasher.FakeVerify(secret)
		return nil, multipass.ErrAccountLocked
	}

	needsRehash, vErr := s.hasher.Verify(user.PasswordHash, secret)
	if vErr != nil {
		if errors.Is(vErr, password.ErrPasswordMismatch) {
			s.recordFailure(ctx, user)
			return nil, multipass.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("local: hash verify: %w", vErr)
	}

	if err := s.users.ResetFailedLogin(ctx, user.ID); err != nil {
		// Non-fatal: log but do not block login.
		_ = err
	}

	if s.rehashOnLogin && needsRehash {
		if newHash, err := s.hasher.Hash(secret); err == nil {
			_ = s.users.UpdatePasswordHash(ctx, user.ID, newHash, user.PasswordVer+1)
		}
	}

	return &multipass.Principal{
		UserID:       user.ID,
		Email:        user.Email,
		Roles:        user.Roles,
		PasswordVer:  user.PasswordVer,
		Extra:        user.Metadata,
		StrategyName: Name,
	}, nil
}

func (s *Strategy) recordFailure(ctx context.Context, u *multipass.User) {
	if s.maxFailedLogins <= 0 {
		_, _ = s.users.IncrementFailedLogin(ctx, u.ID, time.Time{})
		return
	}
	// Speculatively compute lockUntil from the pre-read count. This is
	// correct for the common single-request path. For the concurrent case
	// (multiple simultaneous failures near the threshold) we also check the
	// authoritative post-increment count returned by IncrementFailedLogin.
	var lockUntil time.Time
	if u.FailedLogins+1 >= s.maxFailedLogins {
		lockUntil = s.clock.Now().Add(s.lockoutFor)
	}
	newCount, err := s.users.IncrementFailedLogin(ctx, u.ID, lockUntil)
	if err != nil {
		return
	}
	// Corrective path: if concurrent failures pushed the count over the
	// threshold but the stale pre-read missed it (lockUntil was not passed),
	// apply the lock now. Note that IncrementFailedLogin also increments the
	// counter; SQL implementations should prefer a single conditional UPDATE:
	//   UPDATE users
	//      SET failed_logins = failed_logins + 1,
	//          locked_until  = CASE WHEN failed_logins + 1 >= $threshold
	//                               THEN $lockUntil ELSE locked_until END
	//    WHERE id = $id
	if newCount >= s.maxFailedLogins && lockUntil.IsZero() {
		_, _ = s.users.IncrementFailedLogin(ctx, u.ID, s.clock.Now().Add(s.lockoutFor))
	}
}

// Compile-time interface assertions.
var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.Authenticator = (*Strategy)(nil)
)
