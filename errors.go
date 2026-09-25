package multipass

import (
	"context"
	"errors"
	"log/slog"
)

// Sentinel errors. Wrap them with fmt.Errorf("%w: ...", err) where extra
// context is needed; consumers should compare with errors.Is.
var (
	// ErrInvalidCredentials is returned when the supplied identifier/secret
	// pair does not match any active user. The same error is returned for
	// "user not found" and "wrong password" to prevent account enumeration.
	ErrInvalidCredentials = errors.New("multipass: invalid credentials")

	// ErrUnknownStrategy is returned when a strategy name is not registered
	// in the Service.
	ErrUnknownStrategy = errors.New("multipass: unknown strategy")

	// ErrUnsupportedOperation is returned when a strategy does not implement
	// an optional capability (e.g. Refresh on a session strategy).
	ErrUnsupportedOperation = errors.New("multipass: operation not supported by strategy")

	// ErrTokenExpired is returned when a token is past its exp claim.
	ErrTokenExpired = errors.New("multipass: token expired")

	// ErrTokenInvalid is returned for malformed, badly-signed or
	// claim-mismatched tokens (issuer/audience/nbf/etc.).
	ErrTokenInvalid = errors.New("multipass: token invalid")

	// ErrTokenRevoked is returned when a token's jti / sid is found in the
	// blacklist or has been deleted from the session store.
	ErrTokenRevoked = errors.New("multipass: token revoked")

	// ErrReuseDetected is returned when an already-rotated refresh token is
	// presented for a second time. The whole token family is killed.
	ErrReuseDetected = errors.New("multipass: refresh token reuse detected")

	// ErrAccountLocked is returned after too many failed login attempts.
	ErrAccountLocked = errors.New("multipass: account locked")

	// ErrUserNotFound is an internal sentinel; UserRepository implementations
	// must return this when a user does not exist. The strategy layer
	// translates it to ErrInvalidCredentials.
	ErrUserNotFound = errors.New("multipass: user not found")

	// ErrPasswordMismatch is an internal sentinel returned by the password
	// hasher; strategies translate to ErrInvalidCredentials.
	ErrPasswordMismatch = errors.New("multipass: password mismatch")

	// ErrRateLimited is returned when the optional RateLimiter rejects an
	// operation (e.g. too many magic-link requests for the same email).
	ErrRateLimited = errors.New("multipass: rate limited")

	// ErrTwoFactorRequired is matched (via errors.Is) by the
	// *TwoFactorPendingError that TwoFactorGate.Issue returns when the user
	// must present a second factor. Use errors.As to get the pending token,
	// prompt the user, then call Service.CompleteTwoFactor.
	ErrTwoFactorRequired = errors.New("multipass: second factor required")
)

// ErrorHandler receives errors from side effects that must not fail the
// operation that triggered them — e.g. resetting a failed-login counter
// after a successful login, or deleting a session that is already expired.
// Errors that affect security (recording a failed login, extending a
// session, killing a token family) are always returned, never passed here.
type ErrorHandler func(ctx context.Context, err error)

// DefaultErrorHandler logs err through slog.Default at error level. It is
// the handler strategies use unless configured otherwise.
func DefaultErrorHandler(ctx context.Context, err error) {
	slog.ErrorContext(ctx, "multipass: non-fatal operation failed", "err", err)
}
