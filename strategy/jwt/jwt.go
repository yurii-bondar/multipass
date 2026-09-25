// Package jwt implements the JWT-based authentication strategy.
//
// Highlights:
//
//   - Algorithms whitelisted to EdDSA / RS256 / HS256. The notorious
//     "alg=none" trick is rejected because the parser is configured with
//     ValidMethods.
//   - Short-lived access tokens (default 15 min) with claims iss/sub/aud/
//     exp/iat/nbf/jti.
//   - Long-lived refresh tokens (default 30 days) backed by a server-side
//     RefreshStore. Each refresh rotates the token and atomically marks the
//     previous one as used.
//   - Reuse detection: presenting an already-rotated refresh token kills
//     the entire token family (the user is logged out from every device).
//   - JTI blacklist for emergency revocation of access tokens.
//   - KID-based key rotation via KeyProvider: many keys verify, one signs.
//
// The strategy implements multipass.Strategy + multipass.Refreshable +
// multipass.RevokeAllable.
package jwt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

const Name = "jwt"

// tokenType is encoded in the "typ" private claim so an access token can
// never be presented where a refresh is expected and vice versa.
type tokenType string

const (
	typAccess  tokenType = "access"
	typRefresh tokenType = "refresh"
)

// Claims is the strict claim-set this strategy issues. The standard claims
// follow RFC 7519; "typ" and "fid" are private.
type Claims struct {
	jwtv5.RegisteredClaims
	Type     tokenType `json:"typ,omitempty"`
	FamilyID string    `json:"fid,omitempty"` // refresh-token family
	Email    string    `json:"email,omitempty"`
	Roles    []string  `json:"roles,omitempty"`
	PwdVer   int       `json:"pwd_ver,omitempty"`
}

// Strategy is the JWT auth strategy.
type Strategy struct {
	keys         KeyProvider
	alg          Algorithm
	issuer       string
	audience     []string
	accessTTL    time.Duration
	refreshTTL   time.Duration
	leeway       time.Duration
	clock        multipass.Clock
	idgen        multipass.IDGen
	blacklist    store.Blacklist
	refreshStore store.RefreshStore
	parser       *jwtv5.Parser
}

// Option configures the strategy.
type Option func(*Strategy)

func WithIssuer(iss string) Option           { return func(s *Strategy) { s.issuer = iss } }
func WithAudience(aud ...string) Option      { return func(s *Strategy) { s.audience = aud } }
func WithAccessTTL(d time.Duration) Option   { return func(s *Strategy) { s.accessTTL = d } }
func WithRefreshTTL(d time.Duration) Option  { return func(s *Strategy) { s.refreshTTL = d } }
func WithLeeway(d time.Duration) Option      { return func(s *Strategy) { s.leeway = d } }
func WithClock(c multipass.Clock) Option     { return func(s *Strategy) { s.clock = c } }
func WithIDGen(g multipass.IDGen) Option     { return func(s *Strategy) { s.idgen = g } }
func WithBlacklist(b store.Blacklist) Option { return func(s *Strategy) { s.blacklist = b } }
func WithRefreshStore(r store.RefreshStore) Option {
	return func(s *Strategy) { s.refreshStore = r }
}

// WithAlgorithm overrides the default EdDSA. The same algorithm must be the
// one keys in the KeyProvider were generated for.
func WithAlgorithm(a Algorithm) Option { return func(s *Strategy) { s.alg = a } }

// New constructs the JWT strategy. A KeyProvider is required; everything
// else has sane defaults.
func New(keys KeyProvider, opts ...Option) (*Strategy, error) {
	if keys == nil {
		return nil, errors.New("jwt: KeyProvider is required")
	}
	s := &Strategy{
		keys:       keys,
		alg:        AlgEdDSA,
		accessTTL:  15 * time.Minute,
		refreshTTL: 30 * 24 * time.Hour,
		leeway:     30 * time.Second,
		clock:      multipass.SystemClock(),
		idgen:      multipass.DefaultIDGen(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if _, err := s.alg.signingMethod(); err != nil {
		return nil, err
	}
	// Strict parser: only the configured algorithm is accepted. This
	// closes the alg=none class of attacks at the framework boundary.
	parserOpts := []jwtv5.ParserOption{
		jwtv5.WithValidMethods([]string{string(s.alg)}),
		jwtv5.WithLeeway(s.leeway),
	}
	if s.issuer != "" {
		parserOpts = append(parserOpts, jwtv5.WithIssuer(s.issuer))
	}
	for _, a := range s.audience {
		parserOpts = append(parserOpts, jwtv5.WithAudience(a))
	}
	s.parser = jwtv5.NewParser(parserOpts...)
	return s, nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue generates a fresh access+refresh pair for the given Principal.
//
// Issuing a refresh token requires a configured RefreshStore. Without it,
// the strategy emits only an access token (suitable for purely-stateless API
// designs but you lose rotation/reuse detection). Most applications will
// want to configure a RefreshStore.
func (s *Strategy) Issue(ctx context.Context, p multipass.Principal) (multipass.Credentials, error) {
	now := s.clock.Now()

	accessJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("jwt: gen access jti: %w", err)
	}

	access, accessExp, err := s.signClaims(Claims{
		RegisteredClaims: s.registered(p.UserID, accessJTI, now, now.Add(s.accessTTL)),
		Type:             typAccess,
		Email:            p.Email,
		Roles:            p.Roles,
	})
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
			return multipass.Credentials{}, fmt.Errorf("jwt: gen refresh jti: %w", err)
		}
		familyID := uuid.NewString()
		refreshExp := now.Add(s.refreshTTL)
		refresh, _, err := s.signClaims(Claims{
			RegisteredClaims: s.registered(p.UserID, refreshJTI, now, refreshExp),
			Type:             typRefresh,
			FamilyID:         familyID,
		})
		if err != nil {
			return multipass.Credentials{}, err
		}
		if err := s.refreshStore.Save(ctx, store.RefreshRecord{
			JTI:       refreshJTI,
			UserID:    p.UserID,
			FamilyID:  familyID,
			IssuedAt:  now,
			ExpiresAt: refreshExp,
		}); err != nil {
			return multipass.Credentials{}, fmt.Errorf("jwt: save refresh: %w", err)
		}
		creds.Refresh = refresh
		creds.RefreshExpiry = refreshExp
	}
	return creds, nil
}

// Verify validates an access token (typ=access). Refresh tokens are NOT
// accepted here; use Refresh.
func (s *Strategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	claims, err := s.parse(raw)
	if err != nil {
		return nil, err
	}
	if claims.Type != typAccess {
		return nil, fmt.Errorf("%w: expected access, got %q", multipass.ErrTokenInvalid, claims.Type)
	}
	if s.blacklist != nil && claims.ID != "" {
		blocked, err := s.blacklist.Has(ctx, claims.ID)
		if err != nil {
			return nil, fmt.Errorf("jwt: blacklist lookup: %w", err)
		}
		if blocked {
			return nil, multipass.ErrTokenRevoked
		}
	}
	return claimsToPrincipal(claims), nil
}

// Revoke blacklists the access token's jti until its natural expiry. If no
// blacklist is configured, Revoke is a no-op (and the operation reports
// success — explicit logout is a hint, not a guarantee, in pure-stateless
// JWT setups).
func (s *Strategy) Revoke(ctx context.Context, raw string) error {
	claims, err := s.parseAllowExpired(raw)
	if err != nil {
		return err
	}
	if s.blacklist == nil || claims.ID == "" || claims.ExpiresAt == nil {
		return nil
	}
	return s.blacklist.Add(ctx, claims.ID, claims.ExpiresAt.Time)
}

// RevokeAllForUser kills every refresh token of the user. New access tokens
// signed before this call will keep working until they expire (consider
// embedding pwd_ver in the access token and bumping it on critical events
// to invalidate them globally).
func (s *Strategy) RevokeAllForUser(ctx context.Context, userID string) error {
	if s.refreshStore == nil {
		return fmt.Errorf("%w: no RefreshStore configured", multipass.ErrUnsupportedOperation)
	}
	return s.refreshStore.KillUser(ctx, userID)
}

// ----- helpers -------------------------------------------------------------

func (s *Strategy) registered(sub, jti string, iat, exp time.Time) jwtv5.RegisteredClaims {
	c := jwtv5.RegisteredClaims{
		Subject:   sub,
		ID:        jti,
		IssuedAt:  jwtv5.NewNumericDate(iat),
		NotBefore: jwtv5.NewNumericDate(iat),
		ExpiresAt: jwtv5.NewNumericDate(exp),
	}
	if s.issuer != "" {
		c.Issuer = s.issuer
	}
	if len(s.audience) > 0 {
		c.Audience = jwtv5.ClaimStrings(s.audience)
	}
	return c
}

// signClaims signs the claims with the current key and returns the compact
// JWT plus the exp.Time for caller convenience.
func (s *Strategy) signClaims(c Claims) (string, time.Time, error) {
	method, err := s.alg.signingMethod()
	if err != nil {
		return "", time.Time{}, err
	}
	key, err := s.keys.Current()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt: get current key: %w", err)
	}
	tok := jwtv5.NewWithClaims(method, c)
	tok.Header["kid"] = key.KID
	signKey, err := signKeyOf(key)
	if err != nil {
		return "", time.Time{}, err
	}
	signed, err := tok.SignedString(signKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("jwt: sign: %w", err)
	}
	exp := time.Time{}
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Time
	}
	return signed, exp, nil
}

// parse runs the strict parser. Returns ErrTokenExpired or ErrTokenInvalid
// translated from jwt-go's error set.
func (s *Strategy) parse(raw string) (*Claims, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: empty token", multipass.ErrTokenInvalid)
	}
	claims := &Claims{}
	_, err := s.parser.ParseWithClaims(raw, claims, s.keyFunc())
	if err != nil {
		if errors.Is(err, jwtv5.ErrTokenExpired) {
			return nil, multipass.ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, err)
	}
	return claims, nil
}

// parseAllowExpired re-parses and tolerates expiry (used by Revoke so a user
// can logout an already-expired access token without erroring).
func (s *Strategy) parseAllowExpired(raw string) (*Claims, error) {
	c, err := s.parse(raw)
	if errors.Is(err, multipass.ErrTokenExpired) {
		// Fall back to a permissive parser. We still verify signature.
		permissive := jwtv5.NewParser(
			jwtv5.WithValidMethods([]string{string(s.alg)}),
			jwtv5.WithoutClaimsValidation(),
		)
		c2 := &Claims{}
		_, perr := permissive.ParseWithClaims(raw, c2, s.keyFunc())
		if perr != nil {
			return nil, fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, perr)
		}
		return c2, nil
	}
	return c, err
}

func (s *Strategy) keyFunc() jwtv5.Keyfunc {
	return func(t *jwtv5.Token) (any, error) {
		// Algorithm whitelist is enforced by the parser, but assert again
		// in case of a misconfigured parser.
		if t.Method.Alg() != string(s.alg) {
			return nil, fmt.Errorf("jwt: alg %q not allowed", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		var key Key
		var err error
		if kid != "" {
			key, err = s.keys.ByKID(kid)
		} else {
			key, err = s.keys.Current()
		}
		if err != nil {
			return nil, err
		}
		return verifyKeyOf(key)
	}
}

func claimsToPrincipal(c *Claims) *multipass.Principal {
	p := &multipass.Principal{
		UserID:       c.Subject,
		Email:        c.Email,
		Roles:        c.Roles,
		StrategyName: Name,
		TokenID:      c.ID,
	}
	if c.IssuedAt != nil {
		p.IssuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		p.ExpiresAt = c.ExpiresAt.Time
	}
	if c.PwdVer != 0 {
		if p.Extra == nil {
			p.Extra = make(map[string]any)
		}
		p.Extra["pwd_ver"] = c.PwdVer
	}
	return p
}

// Compile-time assertions.
var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.Refreshable   = (*Strategy)(nil)
	_ multipass.RevokeAllable = (*Strategy)(nil)
)
