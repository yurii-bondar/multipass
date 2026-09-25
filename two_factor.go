package multipass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yurii-bondar/multipass/store"
)

// SecondFactor is satisfied by any strategy usable as a second
// authentication factor. The gate passes the userID it has already
// authenticated with the primary factor, never one supplied by the client,
// so a factor can only ever be checked against the right account. TOTP
// (strategy/magiclink.TOTPStrategy) and Passkeys/WebAuthn
// (strategy/webauthn.Strategy) both implement it.
type SecondFactor interface {
	// VerifySecondFactor returns nil when input (a TOTP code, a WebAuthn
	// assertion envelope, ...) is a valid second factor for userID.
	VerifySecondFactor(ctx context.Context, userID, input string) error
}

// TwoFactorRequirement decides, per user, whether a second factor must be
// presented before Issue is allowed to proceed. A nil TwoFactorRequirement
// makes the gate unconditional: every Issue call demands a second factor.
//
// A typical implementation reads a "2FA enabled" flag the host application
// keeps on its own user record (e.g. User.MFASecret != "").
type TwoFactorRequirement interface {
	Required(ctx context.Context, userID string) (bool, error)
}

// TwoFactorRequirementFunc adapts a plain function to TwoFactorRequirement.
type TwoFactorRequirementFunc func(ctx context.Context, userID string) (bool, error)

// Required implements TwoFactorRequirement.
func (f TwoFactorRequirementFunc) Required(ctx context.Context, userID string) (bool, error) {
	return f(ctx, userID)
}

// TwoFactorPendingError is returned by TwoFactorGate.Issue when the user must
// present a second factor. Token identifies the server-side pending login
// created for the already-authenticated principal; hand it to the client
// (e.g. in a hidden form field or an HttpOnly cookie) and pass it back to
// CompleteTwoFactor together with the code. The token is single-use,
// short-lived and carries no data itself.
//
// errors.Is(err, ErrTwoFactorRequired) reports true for this error.
type TwoFactorPendingError struct {
	Token     string
	ExpiresAt time.Time
}

func (e *TwoFactorPendingError) Error() string { return ErrTwoFactorRequired.Error() }

// Is makes errors.Is(err, ErrTwoFactorRequired) match.
func (e *TwoFactorPendingError) Is(target error) bool { return target == ErrTwoFactorRequired }

// TwoFactorCompleter is implemented by strategies that finish a login
// suspended by a second-factor challenge. TwoFactorGate implements it;
// Service.CompleteTwoFactor dispatches to it.
type TwoFactorCompleter interface {
	CompleteTwoFactor(ctx context.Context, token, input string) (Credentials, error)
}

// TwoFactorGate wraps any issuing Strategy (jwt, paseto, session, apikey,
// webauthn, ...) and enforces a second factor before a credential is minted.
//
// This is a decorator rather than a per-strategy "2FA: true" option:
// every strategy already exposes the same Issue/Verify/Revoke triple, so one
// implementation covers all of them. Wrap whichever strategy issues the
// credential you want gated at Register time:
//
//	totp, _ := magiclink.NewTOTP(totpStore, totpGuard)
//	gate, _ := multipass.RequireTwoFactor(jwtStrategy, totp, pendingStore,
//	    multipass.WithRequirement(multipass.TwoFactorRequirementFunc(
//	        func(ctx context.Context, userID string) (bool, error) {
//	            u, err := users.GetByID(ctx, userID)
//	            if err != nil { return false, err }
//	            return u.MFASecret != "", nil
//	        }),
//	    ))
//	svc.Register(gate)
//	svc.Register(local.New(users, hasher)) // primary factor, left unwrapped
//
// The Name() of the gate is the wrapped strategy's name, so registering the
// gate is a drop-in replacement.
//
// Flow:
//
//  1. Authenticate with the primary strategy and call Issue (or Service.Login).
//  2. If the user is enrolled, Issue stores the authenticated principal as a
//     pending login and returns *TwoFactorPendingError carrying its token.
//  3. Call CompleteTwoFactor(token, code). The gate verifies the code for
//     the principal stored in step 2 and only then calls the wrapped Issue.
//
// The second step cannot be reached without the first: the userID checked
// in step 3 comes from the server-side pending record, not from the client.
type TwoFactorGate struct {
	inner       Strategy
	second      SecondFactor
	pending     store.OTPStore
	required    TwoFactorRequirement
	idgen       IDGen
	clock       Clock
	pendingTTL  time.Duration
	maxAttempts int
}

// TwoFactorOption configures a TwoFactorGate.
type TwoFactorOption func(*TwoFactorGate)

// WithRequirement makes enforcement conditional per user. Without it, every
// Issue call on the wrapped strategy demands a second factor from everyone.
func WithRequirement(r TwoFactorRequirement) TwoFactorOption {
	return func(g *TwoFactorGate) { g.required = r }
}

// WithPendingTTL sets how long a pending login waits for its second factor.
// Default 5 minutes.
func WithPendingTTL(d time.Duration) TwoFactorOption {
	return func(g *TwoFactorGate) { g.pendingTTL = d }
}

// WithMaxAttempts sets how many wrong second-factor inputs a pending login
// tolerates before it is discarded and the user must start over with the
// primary factor. Default 3.
func WithMaxAttempts(n int) TwoFactorOption {
	return func(g *TwoFactorGate) { g.maxAttempts = n }
}

// WithTwoFactorClock overrides the clock (testing).
func WithTwoFactorClock(c Clock) TwoFactorOption {
	return func(g *TwoFactorGate) { g.clock = c }
}

// RequireTwoFactor wraps inner so that Issue additionally demands a second
// factor verified via second. pending stores pending logins between Issue
// and CompleteTwoFactor; its Consume MUST be atomic delete-on-read.
func RequireTwoFactor(inner Strategy, second SecondFactor, pending store.OTPStore, opts ...TwoFactorOption) (*TwoFactorGate, error) {
	if inner == nil || second == nil || pending == nil {
		return nil, errors.New("multipass: RequireTwoFactor needs inner strategy, second factor and pending store")
	}
	g := &TwoFactorGate{
		inner:       inner,
		second:      second,
		pending:     pending,
		idgen:       DefaultIDGen(),
		clock:       SystemClock(),
		pendingTTL:  5 * time.Minute,
		maxAttempts: 3,
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.pendingTTL <= 0 || g.maxAttempts <= 0 {
		return nil, errors.New("multipass: two-factor pending TTL and max attempts must be positive")
	}
	return g, nil
}

// Name implements Strategy. The gate is transparent: it keeps the wrapped
// strategy's registry name so Register/Issue/Verify call sites don't change.
func (g *TwoFactorGate) Name() string { return g.inner.Name() }

// Issue delegates straight to the wrapped strategy for users who do not need
// a second factor. For everyone else it stores p as a pending login and
// returns *TwoFactorPendingError; no credential is minted.
func (g *TwoFactorGate) Issue(ctx context.Context, p Principal) (Credentials, error) {
	if g.required != nil {
		ok, err := g.required.Required(ctx, p.UserID)
		if err != nil {
			return Credentials{}, fmt.Errorf("multipass: two-factor requirement check: %w", err)
		}
		if !ok {
			return g.inner.Issue(ctx, p)
		}
	}
	if p.UserID == "" {
		return Credentials{}, errors.New("multipass: two-factor gate needs Principal.UserID")
	}
	token, err := g.idgen.NewID()
	if err != nil {
		return Credentials{}, fmt.Errorf("multipass: gen pending token: %w", err)
	}
	pl := pendingLogin{Principal: p, ExpiresAt: g.clock.Now().Add(g.pendingTTL)}
	if err := g.savePending(ctx, token, pl); err != nil {
		return Credentials{}, err
	}
	return Credentials{}, &TwoFactorPendingError{Token: token, ExpiresAt: pl.ExpiresAt}
}

// CompleteTwoFactor finishes a pending login: it verifies input as the
// second factor of the principal stored under token and, on success, mints
// the credential with the wrapped strategy. The token is consumed on
// success and after WithMaxAttempts failures.
func (g *TwoFactorGate) CompleteTwoFactor(ctx context.Context, token, input string) (Credentials, error) {
	if token == "" {
		return Credentials{}, ErrTokenInvalid
	}
	payload, err := g.pending.Consume(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Credentials{}, ErrTokenInvalid
		}
		return Credentials{}, fmt.Errorf("multipass: consume pending login: %w", err)
	}
	pl, err := decodePending(payload)
	if err != nil {
		return Credentials{}, ErrTokenInvalid
	}
	if !g.clock.Now().Before(pl.ExpiresAt) {
		return Credentials{}, ErrTokenExpired
	}
	if verr := g.second.VerifySecondFactor(ctx, pl.Principal.UserID, input); verr != nil {
		pl.Attempts++
		if pl.Attempts < g.maxAttempts {
			if serr := g.savePending(ctx, token, pl); serr != nil {
				return Credentials{}, errors.Join(verr, serr)
			}
		}
		return Credentials{}, verr
	}
	return g.inner.Issue(ctx, pl.Principal)
}

// Verify delegates to the wrapped strategy unchanged: the second factor only
// gates minting new credentials, not validating ones already issued.
func (g *TwoFactorGate) Verify(ctx context.Context, raw string) (*Principal, error) {
	return g.inner.Verify(ctx, raw)
}

// Revoke delegates to the wrapped strategy unchanged.
func (g *TwoFactorGate) Revoke(ctx context.Context, raw string) error {
	return g.inner.Revoke(ctx, raw)
}

// Refresh forwards to the wrapped strategy when it implements Refreshable,
// and returns ErrUnsupportedOperation otherwise. A refresh is NOT
// re-challenged for a second factor: the original login already proved it,
// and a refresh token is strategy-internal state the user never re-enters.
func (g *TwoFactorGate) Refresh(ctx context.Context, refreshToken string) (Credentials, error) {
	r, ok := g.inner.(Refreshable)
	if !ok {
		return Credentials{}, fmt.Errorf("%w: %s.Refresh", ErrUnsupportedOperation, g.Name())
	}
	return r.Refresh(ctx, refreshToken)
}

// RevokeAllForUser forwards to the wrapped strategy when it implements
// RevokeAllable, and returns ErrUnsupportedOperation otherwise.
func (g *TwoFactorGate) RevokeAllForUser(ctx context.Context, userID string) error {
	r, ok := g.inner.(RevokeAllable)
	if !ok {
		return fmt.Errorf("%w: %s.RevokeAllForUser", ErrUnsupportedOperation, g.Name())
	}
	return r.RevokeAllForUser(ctx, userID)
}

// Authenticate forwards to the wrapped strategy when it implements
// Authenticator. Gating the primary factor itself (e.g. "local") is unusual
// — the documented pattern is gating the token-issuing strategy — but the
// gate stays a transparent passthrough for every optional capability the
// inner strategy advertises.
func (g *TwoFactorGate) Authenticate(ctx context.Context, identifier, secret string) (*Principal, error) {
	a, ok := g.inner.(Authenticator)
	if !ok {
		return nil, fmt.Errorf("%w: %s.Authenticate", ErrUnsupportedOperation, g.Name())
	}
	return a.Authenticate(ctx, identifier, secret)
}

// ----- pending login persistence --------------------------------------------

const twoFactorPurpose = "multipass:2fa-pending"

// pendingLogin is serialised to a single JSON string inside OTPPayload.Extra
// so it survives any OTPStore backend (SQL/Redis JSON encoding would
// otherwise turn ints into float64s and times into strings field by field).
type pendingLogin struct {
	Principal Principal `json:"principal"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (g *TwoFactorGate) savePending(ctx context.Context, token string, pl pendingLogin) error {
	ttl := pl.ExpiresAt.Sub(g.clock.Now())
	if ttl <= 0 {
		return ErrTokenExpired
	}
	blob, err := json.Marshal(pl)
	if err != nil {
		return fmt.Errorf("multipass: encode pending login: %w", err)
	}
	err = g.pending.Save(ctx, token, store.OTPPayload{
		UserID:  pl.Principal.UserID,
		Purpose: twoFactorPurpose,
		Extra:   map[string]any{"pending": string(blob)},
	}, ttl)
	if err != nil {
		return fmt.Errorf("multipass: save pending login: %w", err)
	}
	return nil
}

func decodePending(p *store.OTPPayload) (pendingLogin, error) {
	if p.Purpose != twoFactorPurpose {
		return pendingLogin{}, errors.New("multipass: not a pending login")
	}
	blob, ok := p.Extra["pending"].(string)
	if !ok {
		return pendingLogin{}, errors.New("multipass: malformed pending login")
	}
	var pl pendingLogin
	if err := json.Unmarshal([]byte(blob), &pl); err != nil {
		return pendingLogin{}, fmt.Errorf("multipass: decode pending login: %w", err)
	}
	return pl, nil
}

var (
	_ Strategy           = (*TwoFactorGate)(nil)
	_ TwoFactorCompleter = (*TwoFactorGate)(nil)
)
