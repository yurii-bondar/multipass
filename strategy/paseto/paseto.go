// Package paseto implements the PASETO v4 authentication strategy.
//
// PASETO ("Platform-Agnostic Security Tokens") fixes most of JWT's footguns:
//
//   - There is no algorithm-confusion class of attacks: the version+purpose
//     pair (here always v4.local or v4.public) is hard-coded into the
//     parser, and there is no "alg" field in the token.
//   - Modern primitives only: XChaCha20+BLAKE2b for v4.local, Ed25519 for
//     v4.public.
//
// This strategy mirrors the JWT strategy: it implements Issue / Verify /
// Refresh / Revoke / RevokeAllForUser using a server-side RefreshStore and
// an optional Blacklist, with refresh-token rotation and reuse detection.
package paseto

import (
	"context"
	"errors"
	"fmt"
	"time"

	pst "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

const Name = "paseto"

// Mode selects the PASETO purpose.
type Mode int

const (
	// ModeLocal uses v4.local (XChaCha20+BLAKE2b symmetric encryption).
	ModeLocal Mode = iota
	// ModePublic uses v4.public (Ed25519-signed, plaintext payload).
	ModePublic
)

// Keys carries the key material the strategy uses. Exactly one of the two
// triples must be populated, matching the chosen Mode.
type Keys struct {
	// v4.local
	Symmetric *pst.V4SymmetricKey
	// v4.public
	Secret *pst.V4AsymmetricSecretKey
	Public *pst.V4AsymmetricPublicKey
}

// Strategy is the PASETO v4 strategy.
type Strategy struct {
	mode         Mode
	keys         Keys
	issuer       string
	audience     string
	accessTTL    time.Duration
	refreshTTL   time.Duration
	clock        multipass.Clock
	idgen        multipass.IDGen
	blacklist    store.Blacklist
	refreshStore store.RefreshStore
}

// Option configures the strategy.
type Option func(*Strategy)

func WithIssuer(iss string) Option           { return func(s *Strategy) { s.issuer = iss } }
func WithAudience(aud string) Option         { return func(s *Strategy) { s.audience = aud } }
func WithAccessTTL(d time.Duration) Option   { return func(s *Strategy) { s.accessTTL = d } }
func WithRefreshTTL(d time.Duration) Option  { return func(s *Strategy) { s.refreshTTL = d } }
func WithClock(c multipass.Clock) Option     { return func(s *Strategy) { s.clock = c } }
func WithIDGen(g multipass.IDGen) Option     { return func(s *Strategy) { s.idgen = g } }
func WithBlacklist(b store.Blacklist) Option { return func(s *Strategy) { s.blacklist = b } }
func WithRefreshStore(r store.RefreshStore) Option {
	return func(s *Strategy) { s.refreshStore = r }
}

// New constructs the PASETO strategy.
func New(mode Mode, keys Keys, opts ...Option) (*Strategy, error) {
	if err := validateKeys(mode, keys); err != nil {
		return nil, err
	}
	s := &Strategy{
		mode:       mode,
		keys:       keys,
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
		clock:      multipass.SystemClock(),
		idgen:      multipass.DefaultIDGen(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func validateKeys(m Mode, k Keys) error {
	switch m {
	case ModeLocal:
		if k.Symmetric == nil {
			return errors.New("paseto: ModeLocal requires Keys.Symmetric")
		}
	case ModePublic:
		if k.Secret == nil || k.Public == nil {
			return errors.New("paseto: ModePublic requires Keys.Secret and Keys.Public")
		}
	default:
		return errors.New("paseto: unknown mode")
	}
	return nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue mints an access+refresh pair. Refresh is only emitted when a
// RefreshStore is configured.
func (s *Strategy) Issue(ctx context.Context, p multipass.Principal) (multipass.Credentials, error) {
	now := s.clock.Now()

	accessJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("paseto: gen access jti: %w", err)
	}
	accessExp := now.Add(s.accessTTL)
	access, err := s.sign(p, accessJTI, "access", "", now, accessExp)
	if err != nil {
		return multipass.Credentials{}, err
	}

	creds := multipass.Credentials{
		Access:       access,
		TokenType:    "Bearer",
		AccessExpiry: accessExp,
		Subject:      p.UserID,
	}

	if s.refreshStore != nil {
		refreshJTI, err := s.idgen.NewID()
		if err != nil {
			return multipass.Credentials{}, fmt.Errorf("paseto: gen refresh jti: %w", err)
		}
		familyID := uuid.NewString()
		refreshExp := now.Add(s.refreshTTL)
		refresh, err := s.sign(p, refreshJTI, "refresh", familyID, now, refreshExp)
		if err != nil {
			return multipass.Credentials{}, err
		}
		if err := s.refreshStore.Save(ctx, store.RefreshRecord{
			JTI: refreshJTI, UserID: p.UserID, FamilyID: familyID,
			IssuedAt: now, ExpiresAt: refreshExp,
		}); err != nil {
			return multipass.Credentials{}, fmt.Errorf("paseto: save refresh: %w", err)
		}
		creds.Refresh = refresh
		creds.RefreshExpiry = refreshExp
	}
	return creds, nil
}

// Verify validates an access PASETO and returns the underlying Principal.
// Refresh tokens are NOT accepted.
func (s *Strategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	tok, err := s.parse(raw)
	if err != nil {
		return nil, err
	}
	typ, _ := tok.GetString("typ")
	if typ != "access" {
		return nil, fmt.Errorf("%w: expected access, got %q", multipass.ErrTokenInvalid, typ)
	}
	jti, _ := tok.GetJti()
	if s.blacklist != nil && jti != "" {
		blocked, err := s.blacklist.Has(ctx, jti)
		if err != nil {
			return nil, fmt.Errorf("paseto: blacklist: %w", err)
		}
		if blocked {
			return nil, multipass.ErrTokenRevoked
		}
	}
	return tokenToPrincipal(tok), nil
}

// Revoke blacklists the access PASETO. No-op when no Blacklist is wired.
func (s *Strategy) Revoke(ctx context.Context, raw string) error {
	tok, err := s.parseAllowExpired(raw)
	if err != nil {
		return err
	}
	if s.blacklist == nil {
		return nil
	}
	jti, _ := tok.GetJti()
	exp, _ := tok.GetExpiration()
	if jti == "" || exp.IsZero() {
		return nil
	}
	return s.blacklist.Add(ctx, jti, exp)
}

// Refresh rotates a refresh PASETO and returns a new pair, with the same
// reuse-detection / family-kill semantics as the JWT strategy.
func (s *Strategy) Refresh(ctx context.Context, refresh string) (multipass.Credentials, error) {
	if s.refreshStore == nil {
		return multipass.Credentials{}, fmt.Errorf("%w: paseto.Refresh requires a RefreshStore", multipass.ErrUnsupportedOperation)
	}
	tok, err := s.parse(refresh)
	if err != nil {
		return multipass.Credentials{}, err
	}
	typ, _ := tok.GetString("typ")
	if typ != "refresh" {
		return multipass.Credentials{}, fmt.Errorf("%w: not a refresh token", multipass.ErrTokenInvalid)
	}
	sub, _ := tok.GetSubject()
	jti, _ := tok.GetJti()
	familyID, _ := tok.GetString("fid")
	if sub == "" || jti == "" || familyID == "" {
		return multipass.Credentials{}, fmt.Errorf("%w: refresh missing claims", multipass.ErrTokenInvalid)
	}

	now := s.clock.Now()
	newAccessJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, err
	}
	newRefreshJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, err
	}
	newRefreshExp := now.Add(s.refreshTTL)

	rec, reused, err := s.refreshStore.RotateAndCheck(ctx, jti, newRefreshJTI, newRefreshExp)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return multipass.Credentials{}, multipass.ErrTokenRevoked
		}
		return multipass.Credentials{}, fmt.Errorf("paseto: rotate: %w", err)
	}
	if reused {
		if err := s.refreshStore.KillFamily(ctx, familyID); err != nil {
			return multipass.Credentials{}, errors.Join(multipass.ErrReuseDetected, fmt.Errorf("paseto: kill family: %w", err))
		}
		return multipass.Credentials{}, multipass.ErrReuseDetected
	}

	email, _ := tok.GetString("email")
	roles, _ := getStringSlice(tok, "roles")

	p := multipass.Principal{UserID: sub, Email: email, Roles: roles}

	access, err := s.sign(p, newAccessJTI, "access", "", now, now.Add(s.accessTTL))
	if err != nil {
		return multipass.Credentials{}, err
	}
	newRefresh, err := s.sign(p, newRefreshJTI, "refresh", rec.FamilyID, now, newRefreshExp)
	if err != nil {
		return multipass.Credentials{}, err
	}
	return multipass.Credentials{
		Access:        access,
		Refresh:       newRefresh,
		TokenType:     "Bearer",
		AccessExpiry:  now.Add(s.accessTTL),
		RefreshExpiry: newRefreshExp,
		Subject:       sub,
	}, nil
}

// RevokeAllForUser kills every refresh token of the user.
func (s *Strategy) RevokeAllForUser(ctx context.Context, userID string) error {
	if s.refreshStore == nil {
		return fmt.Errorf("%w: no RefreshStore", multipass.ErrUnsupportedOperation)
	}
	return s.refreshStore.KillUser(ctx, userID)
}

// ----- helpers -------------------------------------------------------------

func (s *Strategy) tokenFor(p multipass.Principal, jti, typ, fid string, iat, exp time.Time) (pst.Token, error) {
	t := pst.NewToken()
	t.SetSubject(p.UserID)
	t.SetJti(jti)
	t.SetIssuedAt(iat)
	t.SetNotBefore(iat)
	t.SetExpiration(exp)
	t.SetString("typ", typ)
	if s.issuer != "" {
		t.SetIssuer(s.issuer)
	}
	if s.audience != "" {
		t.SetAudience(s.audience)
	}
	if fid != "" {
		t.SetString("fid", fid)
	}
	if p.Email != "" {
		t.SetString("email", p.Email)
	}
	if len(p.Roles) > 0 {
		if err := t.Set("roles", p.Roles); err != nil {
			return pst.Token{}, fmt.Errorf("paseto: set roles: %w", err)
		}
	}
	return t, nil
}

// sign builds and encodes a token in one step.
func (s *Strategy) sign(p multipass.Principal, jti, typ, fid string, iat, exp time.Time) (string, error) {
	t, err := s.tokenFor(p, jti, typ, fid, iat, exp)
	if err != nil {
		return "", err
	}
	return s.encode(t)
}

func (s *Strategy) encode(t pst.Token) (string, error) {
	switch s.mode {
	case ModeLocal:
		return t.V4Encrypt(*s.keys.Symmetric, nil), nil
	case ModePublic:
		return t.V4Sign(*s.keys.Secret, nil), nil
	}
	return "", errors.New("paseto: invalid mode")
}

func (s *Strategy) parse(raw string) (*pst.Token, error) {
	return s.parseWith(raw, false)
}

func (s *Strategy) parseAllowExpired(raw string) (*pst.Token, error) {
	return s.parseWith(raw, true)
}

func (s *Strategy) parseWith(raw string, allowExpired bool) (*pst.Token, error) {
	var parser pst.Parser
	if allowExpired {
		parser = pst.NewParserWithoutExpiryCheck()
	} else {
		parser = pst.NewParser()
		parser.AddRule(pst.NotExpired())
		parser.AddRule(pst.NotBeforeNbf())
	}
	if s.issuer != "" {
		parser.AddRule(pst.IssuedBy(s.issuer))
	}
	if s.audience != "" {
		parser.AddRule(pst.ForAudience(s.audience))
	}

	var tok *pst.Token
	var err error
	switch s.mode {
	case ModeLocal:
		tok, err = parser.ParseV4Local(*s.keys.Symmetric, raw, nil)
	case ModePublic:
		tok, err = parser.ParseV4Public(*s.keys.Public, raw, nil)
	default:
		return nil, errors.New("paseto: invalid mode")
	}
	if err != nil {
		return nil, translatePasetoError(err)
	}
	return tok, nil
}

// translatePasetoError maps go-paseto's error strings to our sentinels.
// The library does not export typed sentinels for expiry vs invalid, so we
// fall back to substring matching — accepted as the cost of using the most
// reliable PASETO impl in Go.
func translatePasetoError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if containsAny(msg, "expired", "ExpiredAt") {
		return multipass.ErrTokenExpired
	}
	return fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, err)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

func tokenToPrincipal(t *pst.Token) *multipass.Principal {
	sub, _ := t.GetSubject()
	jti, _ := t.GetJti()
	email, _ := t.GetString("email")
	iat, _ := t.GetIssuedAt()
	exp, _ := t.GetExpiration()
	roles, _ := getStringSlice(t, "roles")
	return &multipass.Principal{
		UserID:       sub,
		Email:        email,
		Roles:        roles,
		StrategyName: Name,
		TokenID:      jti,
		IssuedAt:     iat,
		ExpiresAt:    exp,
	}
}

func getStringSlice(t *pst.Token, key string) ([]string, error) {
	var v []string
	if err := t.Get(key, &v); err != nil {
		var anySlice []any
		if err2 := t.Get(key, &anySlice); err2 != nil {
			return nil, err
		}
		out := make([]string, 0, len(anySlice))
		for _, x := range anySlice {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out, nil
	}
	return v, nil
}

var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.Refreshable   = (*Strategy)(nil)
	_ multipass.RevokeAllable = (*Strategy)(nil)
)
