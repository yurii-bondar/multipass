package magiclink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/yurii-bondar/multipass"
)

// TOTPSecretStore is the persistence port for TOTP secrets. Each user has
// at most one secret per "purpose" (typically "2fa"). The host application
// wires this into its user table.
type TOTPSecretStore interface {
	GetSecret(ctx context.Context, userID string) (string, error) // base32 secret
}

// TOTPStrategy implements TOTP (RFC 6238) verification as a multipass.Strategy.
//
// Issue is used at enrollment time and returns a Credentials struct whose
// Access is the otpauth:// provisioning URL (so the caller can render a QR
// code) and Refresh is the raw base32 secret (for manual setup).
//
// Verify takes the 6-digit code typed by the user during login. Application
// code is responsible for first authenticating the user with another
// strategy (local password, magic link, …) and then asking for the TOTP
// code on top — this strategy is meant to be used as a 2nd factor.
type TOTPStrategy struct {
	store     TOTPSecretStore
	clock     multipass.Clock
	issuer    string
	digits    otp.Digits
	algorithm otp.Algorithm
	period    uint
	skew      uint
}

// TOTPOption configures TOTPStrategy.
type TOTPOption func(*TOTPStrategy)

// TOTPWithIssuer sets the issuer label that shows in the authenticator app.
func TOTPWithIssuer(s string) TOTPOption { return func(t *TOTPStrategy) { t.issuer = s } }

// TOTPWithSkew sets the number of periods (before/after) accepted to tolerate
// clock drift. Default 1 (i.e. ±30 s with the default 30 s period).
func TOTPWithSkew(s uint) TOTPOption { return func(t *TOTPStrategy) { t.skew = s } }

// TOTPWithClock overrides the clock (testing).
func TOTPWithClock(c multipass.Clock) TOTPOption { return func(t *TOTPStrategy) { t.clock = c } }

// NewTOTP constructs the TOTP strategy.
func NewTOTP(store TOTPSecretStore, opts ...TOTPOption) (*TOTPStrategy, error) {
	if store == nil {
		return nil, errors.New("magiclink: TOTPSecretStore is required")
	}
	t := &TOTPStrategy{
		store:     store,
		clock:     multipass.SystemClock(),
		issuer:    "multipass",
		digits:    otp.DigitsSix,
		algorithm: otp.AlgorithmSHA1, // RFC 6238 default; widest authenticator support
		period:    30,
		skew:      1,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t, nil
}

// Name implements multipass.Strategy.
func (t *TOTPStrategy) Name() string { return "totp" }

// Issue generates a fresh TOTP secret and returns:
//   - Credentials.Access = "otpauth://totp/..." URL (paste into authenticator)
//   - Credentials.Refresh = raw base32 secret
//
// The application must persist the secret server-side (typically via
// UserRepository extension) before the user types their first code.
func (t *TOTPStrategy) Issue(_ context.Context, p multipass.Principal) (multipass.Credentials, error) {
	if p.UserID == "" || p.Email == "" {
		return multipass.Credentials{}, errors.New("magiclink/totp: Principal needs UserID and Email")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      t.issuer,
		AccountName: p.Email,
		Period:      t.period,
		Digits:      t.digits,
		Algorithm:   t.algorithm,
	})
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("totp: generate: %w", err)
	}
	return multipass.Credentials{
		Access:    key.URL(),
		Refresh:   key.Secret(),
		TokenType: "TOTP",
		Subject:   p.UserID,
	}, nil
}

// Verify is invoked with raw of the form "<userID>:<code>". The compound
// form is necessary because TOTP verification is per-user (the secret lives
// in TOTPSecretStore keyed by user id).
func (t *TOTPStrategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	user, code, ok := splitTOTP(raw)
	if !ok {
		return nil, multipass.ErrTokenInvalid
	}
	secret, err := t.store.GetSecret(ctx, user)
	if err != nil || secret == "" {
		return nil, multipass.ErrTokenInvalid
	}
	valid, err := totp.ValidateCustom(code, secret, t.clock.Now(), totp.ValidateOpts{
		Period:    t.period,
		Skew:      t.skew,
		Digits:    t.digits,
		Algorithm: t.algorithm,
	})
	if err != nil || !valid {
		return nil, multipass.ErrTokenInvalid
	}
	return &multipass.Principal{
		UserID:       user,
		StrategyName: t.Name(),
	}, nil
}

// Revoke is a no-op: TOTP secrets are revoked at the user-record level
// (delete the row from TOTPSecretStore). The application owns that lifecycle.
func (t *TOTPStrategy) Revoke(_ context.Context, _ string) error { return nil }

// GenerateCode is a helper for tests/CLI: produces the current 6-digit TOTP
// for a given base32 secret.
func GenerateCode(secret string, at time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}

// splitTOTP parses "<user>:<code>".
func splitTOTP(raw string) (user, code string, ok bool) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == ':' {
			return raw[:i], raw[i+1:], i > 0 && i < len(raw)-1
		}
	}
	return "", "", false
}

var _ multipass.Strategy = (*TOTPStrategy)(nil)
