// Package magiclink implements two related "passwordless" strategies:
//
//   - Magic Link: a one-time URL emailed to the user. Visiting the link
//     consumes the code; on success the strategy returns a Principal that
//     the application can pass to a token strategy (jwt / session / …) to
//     mint the actual session credential.
//   - Numeric OTP: a 6-digit code, suitable for SMS, sharing the same OTP
//     storage and consumption semantics. Construct it via NewNumericOTP.
//     A short numeric code is only unique per recipient, so it is stored
//     under (purpose, recipient, code) and verified as "<recipient>:<code>";
//     verification attempts are rate-limited per recipient.
//
// One-time properties are guaranteed by store.OTPStore.Consume which MUST
// be atomic delete-on-read.
//
// The host application supplies a Sender for delivery (email/SMS) and an
// optional RateLimiter to cap how often Request can be invoked per user.
package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

const Name = "magiclink"

// Sender delivers a generated code/link to the user. The to argument is the
// identifier (email or phone) that was passed to Request. payload is either
// the full URL (for magic links) or the numeric OTP (for SMS).
type Sender interface {
	Send(ctx context.Context, to string, payload string) error
}

// SenderFunc is a convenience adapter so callers can pass a closure.
type SenderFunc func(ctx context.Context, to, payload string) error

func (f SenderFunc) Send(ctx context.Context, to, payload string) error { return f(ctx, to, payload) }

// RateLimiter is a pre-flight budget check keyed by a caller-chosen string.
// It is optional for Request (key: recipient) and required for numeric OTP
// verification (key: "verify:" + recipient). Implementations should return
// multipass.ErrRateLimited when the caller is out of budget.
type RateLimiter interface {
	Allow(ctx context.Context, key string) error
}

// Strategy implements the magic-link / OTP strategy.
type Strategy struct {
	store     store.OTPStore
	sender    Sender
	limiter   RateLimiter
	verifyLim RateLimiter // numeric OTP only: caps guesses per recipient
	users     UserLookup
	clock     multipass.Clock
	ttl       time.Duration
	codeBytes int
	digits    int    // 0 -> base64url; >0 -> digit-only OTP of that length
	urlPrefix string // when set, payload becomes urlPrefix + code
	purpose   string
}

// Option configures the strategy.
type Option func(*Strategy)

// WithTTL sets the lifetime of an issued code. Default 10 minutes.
func WithTTL(d time.Duration) Option { return func(s *Strategy) { s.ttl = d } }

// WithRateLimiter wires an optional rate limiter.
func WithRateLimiter(r RateLimiter) Option { return func(s *Strategy) { s.limiter = r } }

// WithClock overrides the clock (testing).
func WithClock(c multipass.Clock) Option { return func(s *Strategy) { s.clock = c } }

// UserLookup is the slice of multipass.UserRepository Verify needs to check
// the account behind a code; any UserRepository satisfies it.
type UserLookup interface {
	GetByID(ctx context.Context, id string) (*multipass.User, error)
	GetByEmail(ctx context.Context, email string) (*multipass.User, error)
}

// WithUserLookup makes Verify reject codes of disabled accounts, and of
// accounts deleted after the code was issued for a known user id. A code
// issued for an email with no account yet (passwordless sign-up) still
// verifies. Without it Verify does not look at the user at all.
func WithUserLookup(u UserLookup) Option { return func(s *Strategy) { s.users = u } }

// WithURLPrefix turns codes into magic links. Example:
//
//	WithURLPrefix("https://example.com/auth/verify?token=")
func WithURLPrefix(p string) Option { return func(s *Strategy) { s.urlPrefix = p } }

// WithPurpose tags codes (e.g. "login", "password-reset"). Codes generated
// for one purpose cannot be consumed for another.
func WithPurpose(p string) Option { return func(s *Strategy) { s.purpose = p } }

// New constructs the magic-link strategy.
//
//	st     - OTP storage (atomic delete-on-read)
//	sender - delivery transport
func New(st store.OTPStore, sender Sender, opts ...Option) (*Strategy, error) {
	if st == nil {
		return nil, errors.New("magiclink: OTPStore is required")
	}
	if sender == nil {
		return nil, errors.New("magiclink: Sender is required")
	}
	s := &Strategy{
		store:     st,
		sender:    sender,
		clock:     multipass.SystemClock(),
		ttl:       10 * time.Minute,
		codeBytes: 32,
		purpose:   "login",
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// NewNumericOTP constructs a strategy that emits N-digit numeric codes —
// convenient for SMS delivery. The same Sender / OTPStore contract applies.
//
// verifyLimiter is required: a numeric code has only 10^digits values, so
// without a per-recipient cap on Verify it can be guessed. A budget of a few
// attempts per code lifetime (e.g. 5 per 10 minutes) is typical.
func NewNumericOTP(st store.OTPStore, sender Sender, digits int, verifyLimiter RateLimiter, opts ...Option) (*Strategy, error) {
	if digits < 4 || digits > 10 {
		return nil, errors.New("magiclink: digits must be in [4..10]")
	}
	if verifyLimiter == nil {
		return nil, errors.New("magiclink: numeric OTP requires a verify RateLimiter")
	}
	s, err := New(st, sender, opts...)
	if err != nil {
		return nil, err
	}
	s.digits = digits
	s.verifyLim = verifyLimiter
	return s, nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue is not the right entry point for magic-link auth; the typical flow
// is Request (sends a code) then Verify (consumes it). Issue is provided
// for interface symmetry and proxies to Request, treating Principal.Email
// as the destination.
func (s *Strategy) Issue(ctx context.Context, p multipass.Principal) (multipass.Credentials, error) {
	to := p.Email
	if to == "" {
		if v, ok := p.Extra["to"].(string); ok {
			to = v
		}
	}
	if to == "" {
		return multipass.Credentials{}, errors.New("magiclink: Principal.Email or Extra[\"to\"] is required")
	}
	code, err := s.Request(ctx, to, p)
	if err != nil {
		return multipass.Credentials{}, err
	}
	return multipass.Credentials{
		Access:       code,
		TokenType:    "OTP",
		AccessExpiry: s.clock.Now().Add(s.ttl),
		Subject:      p.UserID,
	}, nil
}

// Request creates a fresh code, stores it, and dispatches it via Sender.
// The returned string is the raw code (mostly useful for tests; in
// production the user receives it through Sender, not as a return value).
func (s *Strategy) Request(ctx context.Context, to string, p multipass.Principal) (string, error) {
	if s.limiter != nil {
		if err := s.limiter.Allow(ctx, to); err != nil {
			return "", err
		}
	}
	code, err := s.generate()
	if err != nil {
		return "", err
	}
	if err := s.store.Save(ctx, s.storeKey(to, code), store.OTPPayload{
		UserID:  p.UserID,
		Email:   to,
		Purpose: s.purpose,
		Extra:   p.Extra,
	}, s.ttl); err != nil {
		return "", fmt.Errorf("magiclink: save: %w", err)
	}
	payload := code
	if s.urlPrefix != "" && s.digits == 0 {
		payload = s.urlPrefix + code
	}
	if err := s.sender.Send(ctx, to, payload); err != nil {
		return "", fmt.Errorf("magiclink: send: %w", err)
	}
	return code, nil
}

// Verify consumes a code (single-use, atomic delete-on-read) and returns a
// Principal. The application should then pass that Principal to a token
// strategy (jwt / session / …) to mint the actual session credential.
//
// For magic links raw is the code or the full link. For numeric OTP raw is
// "<recipient>:<code>", where recipient is the same email/phone passed to
// Request.
func (s *Strategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	key, err := s.verifyKey(ctx, strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	payload, err := s.store.Consume(ctx, key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, multipass.ErrTokenInvalid
		}
		return nil, fmt.Errorf("magiclink: consume: %w", err)
	}
	if payload.Purpose != s.purpose {
		return nil, multipass.ErrTokenInvalid
	}
	if err := s.checkUser(ctx, payload); err != nil {
		return nil, err
	}
	return &multipass.Principal{
		UserID:       payload.UserID,
		Email:        payload.Email,
		Extra:        payload.Extra,
		StrategyName: Name,
	}, nil
}

// checkUser applies WithUserLookup to a consumed code.
func (s *Strategy) checkUser(ctx context.Context, p *store.OTPPayload) error {
	if s.users == nil {
		return nil
	}
	var (
		u   *multipass.User
		err error
	)
	switch {
	case p.UserID != "":
		u, err = s.users.GetByID(ctx, p.UserID)
		if errors.Is(err, multipass.ErrUserNotFound) {
			return multipass.ErrInvalidCredentials
		}
	case p.Email != "":
		u, err = s.users.GetByEmail(ctx, p.Email)
		if errors.Is(err, multipass.ErrUserNotFound) {
			return nil // no account yet: passwordless sign-up
		}
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("magiclink: load user: %w", err)
	}
	if u.Disabled {
		return multipass.ErrInvalidCredentials
	}
	return nil
}

// verifyKey turns the raw Verify input into the OTPStore key, applying the
// per-recipient verification budget for numeric codes.
func (s *Strategy) verifyKey(ctx context.Context, raw string) (string, error) {
	if s.digits == 0 {
		code := strings.TrimPrefix(raw, s.urlPrefix)
		if code == "" {
			return "", multipass.ErrTokenInvalid
		}
		return code, nil
	}
	i := strings.LastIndexByte(raw, ':')
	if i <= 0 || i == len(raw)-1 {
		return "", multipass.ErrTokenInvalid
	}
	to, code := raw[:i], raw[i+1:]
	if err := s.verifyLim.Allow(ctx, "verify:"+normalizeRecipient(to)); err != nil {
		return "", err
	}
	return s.storeKey(to, code), nil
}

// storeKey namespaces numeric codes by purpose and recipient: two users can
// legitimately hold the same 6-digit code at the same time, and a code must
// only ever redeem for the recipient it was sent to. Magic-link codes are
// 256-bit random values and are stored as-is.
func (s *Strategy) storeKey(to, code string) string {
	if s.digits == 0 {
		return code
	}
	return "otp\x00" + s.purpose + "\x00" + normalizeRecipient(to) + "\x00" + code
}

func normalizeRecipient(to string) string {
	return strings.ToLower(strings.TrimSpace(to))
}

// Revoke is a no-op: codes are single-use; Consume already deletes them.
// Provided for multipass.Strategy interface conformance.
func (s *Strategy) Revoke(_ context.Context, _ string) error { return nil }

func (s *Strategy) generate() (string, error) {
	if s.digits > 0 {
		return randomDigits(s.digits)
	}
	buf := make([]byte, s.codeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomDigits(n int) (string, error) {
	max := big.NewInt(10)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = byte('0' + v.Int64())
	}
	return string(out), nil
}

var _ multipass.Strategy = (*Strategy)(nil)
