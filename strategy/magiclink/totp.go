package magiclink

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
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
//
// Every accepted code is recorded in a store.TOTPGuard so it can never be
// used twice (RFC 6238 §5.2), and verification attempts are capped per user
// (TOTPWithMaxAttempts) so the code cannot be brute-forced.
type TOTPStrategy struct {
	store     TOTPSecretStore
	guard     store.TOTPGuard
	clock     multipass.Clock
	issuer    string
	digits    otp.Digits
	algorithm otp.Algorithm
	period    uint
	skew      uint

	maxAttempts   int
	attemptWindow time.Duration
}

// TOTPOption configures TOTPStrategy.
type TOTPOption func(*TOTPStrategy)

// TOTPWithIssuer sets the issuer label that shows in the authenticator app.
func TOTPWithIssuer(s string) TOTPOption { return func(t *TOTPStrategy) { t.issuer = s } }

// TOTPWithSkew sets the number of periods (before/after) accepted to tolerate
// clock drift. Default 1 (i.e. ±30 s with the default 30 s period).
func TOTPWithSkew(s uint) TOTPOption { return func(t *TOTPStrategy) { t.skew = s } }

// TOTPWithMaxAttempts caps verification attempts per user: after n attempts
// within window every further attempt fails with multipass.ErrRateLimited
// until the window elapses. A successful verification resets the counter.
// Default 5 attempts per 15 minutes.
func TOTPWithMaxAttempts(n int, window time.Duration) TOTPOption {
	return func(t *TOTPStrategy) { t.maxAttempts, t.attemptWindow = n, window }
}

// TOTPWithClock overrides the clock (testing).
func TOTPWithClock(c multipass.Clock) TOTPOption { return func(t *TOTPStrategy) { t.clock = c } }

// NewTOTP constructs the TOTP strategy. Both the secret store and the replay
// / attempt guard are required.
func NewTOTP(secrets TOTPSecretStore, guard store.TOTPGuard, opts ...TOTPOption) (*TOTPStrategy, error) {
	if secrets == nil {
		return nil, errors.New("magiclink: TOTPSecretStore is required")
	}
	if guard == nil {
		return nil, errors.New("magiclink: store.TOTPGuard is required")
	}
	t := &TOTPStrategy{
		store:         secrets,
		guard:         guard,
		maxAttempts:   5,
		attemptWindow: 15 * time.Minute,
		clock:         multipass.SystemClock(),
		issuer:        "multipass",
		digits:        otp.DigitsSix,
		algorithm:     otp.AlgorithmSHA1, // RFC 6238 default; widest authenticator support
		period:        30,
		skew:          1,
	}
	for _, opt := range opts {
		opt(t)
	}
	if t.maxAttempts <= 0 || t.attemptWindow <= 0 {
		return nil, errors.New("magiclink: TOTPWithMaxAttempts requires n > 0 and window > 0")
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
	if err := t.verify(ctx, user, code); err != nil {
		return nil, err
	}
	return &multipass.Principal{
		UserID:       user,
		StrategyName: t.Name(),
	}, nil
}

// VerifySecondFactor implements multipass.SecondFactor: code is the digits
// the user typed, userID the account already authenticated by the primary
// factor.
func (t *TOTPStrategy) VerifySecondFactor(ctx context.Context, userID, code string) error {
	if userID == "" || code == "" {
		return multipass.ErrTokenInvalid
	}
	return t.verify(ctx, userID, code)
}

// verify checks code for userID in this order: attempt budget, code
// validity, replay. The attempt is counted before anything else so that a
// brute-force run is throttled regardless of which check it would fail.
func (t *TOTPStrategy) verify(ctx context.Context, userID, code string) error {
	n, err := t.guard.Attempt(ctx, userID, t.attemptWindow)
	if err != nil {
		return fmt.Errorf("totp: record attempt: %w", err)
	}
	if n > t.maxAttempts {
		return multipass.ErrRateLimited
	}
	secret, err := t.store.GetSecret(ctx, userID)
	if err != nil || secret == "" {
		return multipass.ErrTokenInvalid
	}
	step, ok, err := t.match(code, secret)
	if err != nil {
		return fmt.Errorf("totp: generate code: %w", err)
	}
	if !ok {
		return multipass.ErrTokenInvalid
	}
	fresh, err := t.guard.AdvanceStep(ctx, userID, step)
	if err != nil {
		return fmt.Errorf("totp: record used step: %w", err)
	}
	if !fresh {
		return multipass.ErrTokenInvalid
	}
	if err := t.guard.ResetAttempts(ctx, userID); err != nil {
		return fmt.Errorf("totp: reset attempts: %w", err)
	}
	return nil
}

// match reports whether code is valid for secret within ±skew periods of
// now and, if so, which RFC 6238 time counter it belongs to. The caller needs
// the counter to reject replays. Every candidate window is compared so the
// run time does not depend on which one matches.
func (t *TOTPStrategy) match(code, secret string) (step int64, ok bool, err error) {
	if len(code) != t.digits.Length() {
		return 0, false, nil
	}
	opts := totp.ValidateOpts{
		Period:    t.period,
		Digits:    t.digits,
		Algorithm: t.algorithm,
	}
	period := int64(t.period)
	current := t.clock.Now().Unix() / period
	skew := int64(t.skew)
	for c := current - skew; c <= current+skew; c++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(c*period, 0), opts)
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !ok {
			step, ok = c, true
		}
	}
	return step, ok, nil
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

var (
	_ multipass.Strategy     = (*TOTPStrategy)(nil)
	_ multipass.SecondFactor = (*TOTPStrategy)(nil)
)
