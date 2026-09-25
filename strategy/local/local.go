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
//     so it survives process restarts. A locked account answers with the
//     same ErrInvalidCredentials as a wrong password, so the lock does not
//     reveal that the account exists.
//
// Lockout is keyed by account, so anyone who knows an email can lock its
// owner out for the lockout window. Throttle login attempts per client
// (IP, device) in the application in front of Authenticate; the library
// has no view of the client.
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
	onError         multipass.ErrorHandler
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

// WithErrorHandler receives errors from non-fatal side effects of a
// successful login (resetting the failed-login counter, re-hashing the
// password). Default multipass.DefaultErrorHandler.
func WithErrorHandler(h multipass.ErrorHandler) Option { return func(s *Strategy) { s.onError = h } }

// New constructs a local strategy.
func New(users multipass.UserRepository, hasher *password.Hasher, opts ...Option) *Strategy {
	s := &Strategy{
		users:           users,
		hasher:          hasher,
		clock:           multipass.SystemClock(),
		maxFailedLogins: 10,
		lockoutFor:      15 * time.Minute,
		rehashOnLogin:   true,
		onError:         multipass.DefaultErrorHandler,
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
		return nil, multipass.ErrInvalidCredentials
	}

	needsRehash, vErr := s.hasher.Verify(user.PasswordHash, secret)
	if vErr != nil {
		if errors.Is(vErr, password.ErrPasswordMismatch) {
			if err := s.recordFailure(ctx, user); err != nil {
				return nil, fmt.Errorf("local: record failed login: %w", err)
			}
			return nil, multipass.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("local: hash verify: %w", vErr)
	}

	// The password is correct: failures below are housekeeping and must not
	// turn a valid login into an error.
	if err := s.users.ResetFailedLogin(ctx, user.ID); err != nil {
		s.onError(ctx, fmt.Errorf("local: reset failed logins: %w", err))
	}
	if s.rehashOnLogin && needsRehash {
		s.rehash(ctx, user, secret)
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

// rehash upgrades the stored hash to the current parameters. The password
// itself is unchanged, so PasswordVer is kept: bumping it would revoke every
// token the user holds just because the hash format moved on.
func (s *Strategy) rehash(ctx context.Context, u *multipass.User, secret string) {
	newHash, err := s.hasher.Hash(secret)
	if err != nil {
		s.onError(ctx, fmt.Errorf("local: rehash password: %w", err))
		return
	}
	if err := s.users.UpdatePasswordHash(ctx, u.ID, newHash, u.PasswordVer); err != nil {
		s.onError(ctx, fmt.Errorf("local: store rehashed password: %w", err))
	}
}

// recordFailure increments the failed-login counter and applies the lockout.
// Its error is returned to the caller: if the counter cannot be written, the
// brute-force protection is not in effect and the attempt must not look like
// an ordinary wrong password.
func (s *Strategy) recordFailure(ctx context.Context, u *multipass.User) error {
	if s.maxFailedLogins <= 0 {
		_, err := s.users.IncrementFailedLogin(ctx, u.ID, time.Time{})
		return err
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
		return err
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
		if _, err := s.users.IncrementFailedLogin(ctx, u.ID, s.clock.Now().Add(s.lockoutFor)); err != nil {
			return err
		}
	}
	return nil
}

// Compile-time interface assertions.
var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.Authenticator = (*Strategy)(nil)
)
