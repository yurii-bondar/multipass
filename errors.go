package multipass

import "errors"

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

	// ErrTwoFactorRequired is returned by TwoFactorGate.Issue when the caller
	// is enrolled in 2FA but Principal.Extra does not carry a second-factor
	// code/assertion yet. Applications should catch this and prompt the user
	// for their second factor instead of treating it as a hard failure.
	ErrTwoFactorRequired = errors.New("multipass: second factor required")
)
