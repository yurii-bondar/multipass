// Package multipass is a pluggable, framework-agnostic authentication library
// for Go. It is conceptually inspired by Passport.js: every authentication
// method (JWT, PASETO, opaque sessions, API keys, magic links, ...) is a
// Strategy that satisfies a single small interface and is registered on a
// Service.
//
// Design rules
//
//  1. The library never imports a database driver, a cache client, or an HTTP
//     framework. All side-effects go through interfaces that the host
//     application implements (see UserRepository in ports.go and the *Store
//     interfaces in store/store.go).
//
//  2. The core works with raw strings (token, sid, api key). HTTP plumbing is
//     opt-in and lives under transport/.
//
//  3. Strategies expose the same triple — Issue / Verify / Revoke — so they
//     are interchangeable from the bussiness-logic point of view. Optional
//     capabilities (refresh, revoke-all, …) are advertised via narrow
//     interfaces that callers detect with a type assertion.
package multipass

import (
	"context"
	"fmt"
	"sync"
)

// Strategy is the core extension point of the library. Every authentication
// method implements it.
//
// Implementations MUST be safe for concurrent use by multiple goroutines.
type Strategy interface {
	// Name is used as the lookup key inside the Service registry. It must be
	// stable and unique across registered strategies. Conventional names:
	// "jwt", "paseto", "session", "apikey", "local", "magiclink", "totp".
	Name() string

	// Issue creates a new credential for the given Principal. Called after
	// the Service has already validated the user (e.g. local password check).
	Issue(ctx context.Context, p Principal) (Credentials, error)

	// Verify validates a raw credential string and returns the Principal it
	// represents. Returns ErrTokenInvalid / ErrTokenExpired / ErrTokenRevoked
	// for the obvious cases.
	Verify(ctx context.Context, raw string) (*Principal, error)

	// Revoke invalidates a single credential (logout). For stateless
	// strategies this typically adds the jti to a blacklist; for stateful
	// strategies it removes the record from the store. Idempotent: revoking
	// a non-existing credential is not an error.
	Revoke(ctx context.Context, raw string) error
}

// Refreshable is implemented by strategies that support sliding-window token
// renewal. JWT and PASETO advertise it; Session and API-Key do not.
type Refreshable interface {
	Refresh(ctx context.Context, refreshToken string) (Credentials, error)
}

// RevokeAllable is implemented by strategies that can wipe every credential
// for a given user (logout-from-all-devices). Session and JWT (with refresh
// store) advertise it.
type RevokeAllable interface {
	RevokeAllForUser(ctx context.Context, userID string) error
}

// Authenticator is the contract a strategy MAY implement when it wants the
// Service to drive the credential check itself. The local strategy (email +
// password) implements this; token-bearing strategies do not.
//
// The Service exposes Service.Authenticate which delegates to this method on
// the named strategy.
type Authenticator interface {
	Authenticate(ctx context.Context, identifier, secret string) (*Principal, error)
}

// Service is the facade application code talks to. It owns the strategy
// registry and a few cross-cutting collaborators (UserRepository, Clock).
//
// A zero Service is NOT usable; construct via New.
type Service struct {
	users UserRepository
	clock Clock

	mu         sync.RWMutex
	strategies map[string]Strategy
}

// Option customises the Service.
type Option func(*Service)

// WithClock overrides the default system clock (useful in tests).
func WithClock(c Clock) Option { return func(s *Service) { s.clock = c } }

// New builds a Service with the given user repository and options. At least
// one strategy must be Register-ed before authenticating.
func New(users UserRepository, opts ...Option) *Service {
	s := &Service{
		users:      users,
		clock:      SystemClock(),
		strategies: make(map[string]Strategy),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Register adds a strategy to the registry. Panics if a strategy with the
// same name is already registered — registration mistakes should fail loudly
// at startup.
func (s *Service) Register(st Strategy) {
	if st == nil {
		panic("multipass: Register(nil)")
	}
	name := st.Name()
	if name == "" {
		panic("multipass: strategy with empty Name()")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.strategies[name]; exists {
		panic(fmt.Sprintf("multipass: strategy %q already registered", name))
	}
	s.strategies[name] = st
}

// Strategy returns the named strategy or ErrUnknownStrategy.
func (s *Service) Strategy(name string) (Strategy, error) {
	s.mu.RLock()
	st, ok := s.strategies[name]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownStrategy, name)
	}
	return st, nil
}

// Users exposes the configured UserRepository. Strategies that need
// repository access (e.g. local) accept it directly via their constructor;
// this getter is for application code.
func (s *Service) Users() UserRepository { return s.users }

// Clock returns the configured clock.
func (s *Service) Clock() Clock { return s.clock }

// Authenticate runs the Authenticator method of the named strategy. Returns
// ErrUnsupportedOperation if the strategy does not implement it.
func (s *Service) Authenticate(ctx context.Context, strategy, identifier, secret string) (*Principal, error) {
	st, err := s.Strategy(strategy)
	if err != nil {
		return nil, err
	}
	a, ok := st.(Authenticator)
	if !ok {
		return nil, fmt.Errorf("%w: %s.Authenticate", ErrUnsupportedOperation, strategy)
	}
	return a.Authenticate(ctx, identifier, secret)
}

// Login authenticates a user (via the named Authenticator strategy) and then
// issues credentials with the named issuing strategy. The two strategies may
// be the same (e.g. session) or different (verify with "local", issue with
// "jwt").
//
// Typical use:
//
//	creds, err := svc.Login(ctx, "local", "jwt", email, password)
func (s *Service) Login(ctx context.Context, verifyStrategy, issueStrategy, identifier, secret string) (Credentials, error) {
	p, err := s.Authenticate(ctx, verifyStrategy, identifier, secret)
	if err != nil {
		return Credentials{}, err
	}
	return s.Issue(ctx, issueStrategy, *p)
}

// Issue creates new credentials with the named strategy.
func (s *Service) Issue(ctx context.Context, strategy string, p Principal) (Credentials, error) {
	st, err := s.Strategy(strategy)
	if err != nil {
		return Credentials{}, err
	}
	if p.StrategyName == "" {
		p.StrategyName = strategy
	}
	return st.Issue(ctx, p)
}

// Verify validates a raw credential against the named strategy.
func (s *Service) Verify(ctx context.Context, strategy, raw string) (*Principal, error) {
	st, err := s.Strategy(strategy)
	if err != nil {
		return nil, err
	}
	return st.Verify(ctx, raw)
}

// Refresh renews credentials. The strategy must implement Refreshable.
func (s *Service) Refresh(ctx context.Context, strategy, refresh string) (Credentials, error) {
	st, err := s.Strategy(strategy)
	if err != nil {
		return Credentials{}, err
	}
	r, ok := st.(Refreshable)
	if !ok {
		return Credentials{}, fmt.Errorf("%w: %s.Refresh", ErrUnsupportedOperation, strategy)
	}
	return r.Refresh(ctx, refresh)
}

// Revoke invalidates a single credential.
func (s *Service) Revoke(ctx context.Context, strategy, raw string) error {
	st, err := s.Strategy(strategy)
	if err != nil {
		return err
	}
	return st.Revoke(ctx, raw)
}

// RevokeAllForUser kills every credential of the user across the named
// strategy. Strategy must implement RevokeAllable.
func (s *Service) RevokeAllForUser(ctx context.Context, strategy, userID string) error {
	st, err := s.Strategy(strategy)
	if err != nil {
		return err
	}
	r, ok := st.(RevokeAllable)
	if !ok {
		return fmt.Errorf("%w: %s.RevokeAllForUser", ErrUnsupportedOperation, strategy)
	}
	return r.RevokeAllForUser(ctx, userID)
}
