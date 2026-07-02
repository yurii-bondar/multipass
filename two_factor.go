package multipass

import (
	"context"
	"fmt"
)

// SecondFactor is satisfied by any strategy usable as a second
// authentication factor — its Verify method is all a gate needs. TOTP
// (strategy/magiclink.TOTPStrategy) and Passkeys/WebAuthn
// (strategy/webauthn.Strategy) both already implement the full Strategy
// interface, which is a superset of this one, so either can be passed to
// RequireTwoFactor unmodified.
type SecondFactor interface {
	Verify(ctx context.Context, raw string) (*Principal, error)
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

// TwoFactorGate wraps any issuing Strategy (jwt, paseto, session, apikey,
// webauthn, ...) and enforces a second factor before Issue is allowed to
// mint a credential.
//
// This is a decorator rather than a per-strategy "2FA: true" option:
// every strategy already exposes the same Issue/Verify/Revoke triple (see
// the design rules in doc.go), so one implementation covers all of them
// instead of duplicating second-factor plumbing seven times. Wrap whichever
// strategy issues the credential you want gated at Register time:
//
//	totp, _ := magiclink.NewTOTP(totpStore)
//	svc.Register(multipass.RequireTwoFactor(jwtStrategy, totp,
//	    multipass.WithRequirement(multipass.TwoFactorRequirementFunc(
//	        func(ctx context.Context, userID string) (bool, error) {
//	            u, err := users.GetByID(ctx, userID)
//	            if err != nil { return false, err }
//	            return u.MFASecret != "", nil
//	        }),
//	    )))
//	svc.Register(local.New(users, hasher)) // primary factor, left unwrapped
//
// The Name() of the gate is the wrapped strategy's name, so registering the
// gate is a drop-in replacement — application code that calls
// svc.Issue(ctx, "jwt", principal) does not change.
//
// Flow:
//
//  1. Authenticate with the primary strategy (local, magiclink, webauthn, ...).
//  2. Call Issue on the gated strategy without a 2FA code. If the user is
//     enrolled, ErrTwoFactorRequired comes back — prompt for the code.
//  3. Retry Issue with Principal.Extra["2fa_code"] (configurable via
//     WithExtraKey) set to the TOTP digits ("<userID>:<code>" — see
//     magiclink.TOTPStrategy.Verify) or a WebAuthn Verify envelope.
type TwoFactorGate struct {
	inner    Strategy
	second   SecondFactor
	required TwoFactorRequirement
	extraKey string
}

// TwoFactorOption configures a TwoFactorGate.
type TwoFactorOption func(*TwoFactorGate)

// WithRequirement makes enforcement conditional per user. Without it, every
// Issue call on the wrapped strategy demands a second factor from everyone.
func WithRequirement(r TwoFactorRequirement) TwoFactorOption {
	return func(g *TwoFactorGate) { g.required = r }
}

// WithExtraKey overrides the Principal.Extra key carrying the second-factor
// code/assertion. Default "2fa_code".
func WithExtraKey(key string) TwoFactorOption {
	return func(g *TwoFactorGate) { g.extraKey = key }
}

// RequireTwoFactor wraps inner so that Issue additionally verifies a second
// factor via second before delegating.
func RequireTwoFactor(inner Strategy, second SecondFactor, opts ...TwoFactorOption) *TwoFactorGate {
	g := &TwoFactorGate{inner: inner, second: second, extraKey: "2fa_code"}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Name implements Strategy. The gate is transparent: it keeps the wrapped
// strategy's registry name so Register/Issue/Verify call sites don't change.
func (g *TwoFactorGate) Name() string { return g.inner.Name() }

// Issue enforces the second factor (subject to WithRequirement) before
// delegating to the wrapped strategy's Issue.
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
	raw, _ := p.Extra[g.extraKey].(string)
	if raw == "" {
		return Credentials{}, ErrTwoFactorRequired
	}
	verified, err := g.second.Verify(ctx, raw)
	if err != nil {
		return Credentials{}, err
	}
	if p.UserID != "" && verified.UserID != "" && verified.UserID != p.UserID {
		return Credentials{}, ErrInvalidCredentials
	}
	return g.inner.Issue(ctx, p)
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
// re-challenged for a second factor: the original Issue already proved it,
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

var _ Strategy = (*TwoFactorGate)(nil)
