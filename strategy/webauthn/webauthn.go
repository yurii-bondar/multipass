// Package webauthn implements Passkeys / FIDO2 WebAuthn as a multipass.Strategy.
//
// WebAuthn is the credential-management API that lets a browser create and
// use a public-key pair on the user's behalf, backed by a platform
// authenticator (Face ID / Touch ID / Windows Hello) or a roaming one
// (security key). The private key never leaves the device and the browser
// refuses to use it outside the origin it was created for, which is what
// makes passkeys phishing-resistant: a lookalike domain simply cannot obtain
// a signature.
//
// Unlike password or token-bearing strategies, WebAuthn is a two-phase
// ceremony driven by the browser's navigator.credentials API:
//
//	registration : BeginRegistration -> browser -> FinishRegistration
//	login        : BeginLogin / BeginDiscoverableLogin -> browser -> FinishLogin
//
// The sessionID returned by every Begin* call must be round-tripped by the
// caller (e.g. a short-lived HttpOnly cookie or a hidden field) and handed
// back to the matching Finish* call; the pending challenge itself is kept
// server-side, reusing store.OTPStore's atomic delete-on-read semantics
// (a WebAuthn challenge is, in every way that matters, a single-use code
// with a TTL).
//
// multipass.Strategy conformance:
//   - Issue is unsupported: registration does not fit a single
//     Principal-in/Credentials-out call. Use BeginRegistration /
//     FinishRegistration directly.
//   - Verify accepts a JSON envelope
//     {"session_id":"...","credential":<raw PublicKeyCredential JSON>} and
//     drives FinishLogin. Prefer calling BeginLogin/FinishLogin directly
//     when you control the transport, since Verify's raw-string signature
//     loses type information.
//
// A successful login only authenticates the Principal; minting an actual
// access credential is left to a token strategy (jwt / paseto / session),
// exactly like the local and magiclink strategies.
package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

const Name = "webauthn"

const challengePurpose = "webauthn"

// UserLookup resolves the multipass.User a ceremony operates on. It is
// intentionally narrower than the full multipass.UserRepository so hosts
// that only expose read access to their user table can still wire this
// strategy up.
type UserLookup interface {
	GetByID(ctx context.Context, userID string) (*multipass.User, error)
}

// Strategy implements Passkey / FIDO2 registration and login.
type Strategy struct {
	rp    *gowebauthn.WebAuthn
	users UserLookup
	creds store.CredentialStore
	otp   store.OTPStore
	clock multipass.Clock
	ttl   time.Duration
}

// Option configures the strategy.
type Option func(*Strategy)

// WithTTL sets how long a pending registration/login challenge stays valid.
// Default 5 minutes.
func WithTTL(d time.Duration) Option { return func(s *Strategy) { s.ttl = d } }

// WithClock overrides the clock (testing).
func WithClock(c multipass.Clock) Option { return func(s *Strategy) { s.clock = c } }

// New constructs the WebAuthn strategy.
//
//	cfg   - Relying Party configuration (RPID, RPDisplayName, RPOrigins, ...);
//	        see gowebauthn.Config. RPID must be the effective domain
//	        ("example.com"), RPOrigins the fully-qualified origins allowed to
//	        complete a ceremony ("https://example.com").
//	users - resolves a multipass.User by id; needed to rebuild the WebAuthn
//	        user handle and, for discoverable/usernameless login, to look the
//	        user up from the credential's user handle alone.
//	creds - persists passkeys. One user typically owns several (one per
//	        device); see store.CredentialStore.
//	otp   - stores pending challenges between Begin* and Finish*. The
//	        magiclink/OTP infrastructure is reused here since the atomic
//	        delete-on-read + TTL semantics are identical.
func New(cfg *gowebauthn.Config, users UserLookup, creds store.CredentialStore, otp store.OTPStore, opts ...Option) (*Strategy, error) {
	if users == nil {
		return nil, errors.New("webauthn: UserLookup is required")
	}
	if creds == nil {
		return nil, errors.New("webauthn: CredentialStore is required")
	}
	if otp == nil {
		return nil, errors.New("webauthn: OTPStore is required")
	}
	rp, err := gowebauthn.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("webauthn: config: %w", err)
	}
	s := &Strategy{
		rp:    rp,
		users: users,
		creds: creds,
		otp:   otp,
		clock: multipass.SystemClock(),
		ttl:   5 * time.Minute,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Name implements multipass.Strategy.
func (s *Strategy) Name() string { return Name }

// Issue is not the right entry point for WebAuthn: registration is a
// two-phase ceremony. Provided for interface conformance only.
func (s *Strategy) Issue(_ context.Context, _ multipass.Principal) (multipass.Credentials, error) {
	return multipass.Credentials{}, fmt.Errorf("%w: webauthn.Issue (use BeginRegistration/FinishRegistration)", multipass.ErrUnsupportedOperation)
}

// verifyEnvelope is the shape Verify expects when driven through the
// generic multipass.Strategy interface.
type verifyEnvelope struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// Verify implements multipass.Strategy by unwrapping a JSON envelope of
// {session_id, credential} and delegating to FinishLogin. Prefer calling
// FinishLogin directly when you have access to the original *http.Request.
func (s *Strategy) Verify(ctx context.Context, raw string) (*multipass.Principal, error) {
	var env verifyEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil || env.SessionID == "" || len(env.Credential) == 0 {
		return nil, multipass.ErrTokenInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(env.Credential))
	if err != nil {
		return nil, fmt.Errorf("webauthn: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return s.FinishLogin(ctx, env.SessionID, req)
}

// Revoke removes a single passkey. raw is the credential ID, base64url
// (RawURLEncoding) encoded — the same encoding used for Principal.TokenID
// after a successful login. Idempotent: revoking an unknown id is not an
// error.
func (s *Strategy) Revoke(ctx context.Context, raw string) error {
	id, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return multipass.ErrTokenInvalid
	}
	if err := s.creds.Delete(ctx, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("webauthn: delete credential: %w", err)
	}
	return nil
}

// RevokeAllForUser deletes every passkey belonging to userID. Implements
// multipass.RevokeAllable.
func (s *Strategy) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.creds.DeleteByUser(ctx, userID)
}

// ListCredentials returns every passkey registered for userID — handy for a
// "manage your passkeys" account page.
func (s *Strategy) ListCredentials(ctx context.Context, userID string) ([]store.WebAuthnCredential, error) {
	return s.creds.ListByUser(ctx, userID)
}

// BeginRegistration starts a registration ceremony for an already
// authenticated user (the caller is responsible for having established that
// u is who they claim to be, e.g. via a session cookie, before offering to
// add a passkey). Marshal the returned *protocol.CredentialCreation
// directly as the JSON body of your "/webauthn/register/start" response;
// the browser passes it to navigator.credentials.create().
func (s *Strategy) BeginRegistration(ctx context.Context, u *multipass.User, opts ...gowebauthn.RegistrationOption) (creation *protocol.CredentialCreation, sessionID string, err error) {
	if u == nil || u.ID == "" {
		return nil, "", errors.New("webauthn: user is required")
	}
	wu, err := s.buildUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	creation, session, err := s.rp.BeginRegistration(wu, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin registration: %w", err)
	}
	sessionID, err = s.saveSession(ctx, "register", u.ID, session)
	if err != nil {
		return nil, "", err
	}
	return creation, sessionID, nil
}

// FinishRegistration completes a registration ceremony started by
// BeginRegistration. r must carry the raw JSON body produced by the
// browser's navigator.credentials.create() response
// (PublicKeyCredential.toJSON()). name is an optional user-facing label for
// the new passkey (e.g. "MacBook Touch ID"); pass "" if you don't collect
// one.
func (s *Strategy) FinishRegistration(ctx context.Context, sessionID, name string, r *http.Request) (*store.WebAuthnCredential, error) {
	userID, session, err := s.consumeSession(ctx, "register", sessionID)
	if err != nil {
		return nil, err
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: load user: %w", err)
	}
	wu, err := s.buildUser(ctx, u)
	if err != nil {
		return nil, err
	}
	cred, err := s.rp.FinishRegistration(wu, *session, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, err)
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("webauthn: marshal credential: %w", err)
	}
	rec := store.WebAuthnCredential{
		ID:        cred.ID,
		UserID:    userID,
		Name:      name,
		Data:      data,
		CreatedAt: s.clock.Now(),
	}
	if err := s.creds.Save(ctx, rec); err != nil {
		return nil, fmt.Errorf("webauthn: save credential: %w", err)
	}
	return &rec, nil
}

// BeginLogin starts a non-discoverable login ceremony for a known user
// (identifier already established, e.g. typed into an email field before
// the passkey prompt). Use BeginDiscoverableLogin for usernameless passkey
// autofill instead.
func (s *Strategy) BeginLogin(ctx context.Context, userID string, opts ...gowebauthn.LoginOption) (assertion *protocol.CredentialAssertion, sessionID string, err error) {
	if userID == "" {
		return nil, "", errors.New("webauthn: userID is required")
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: load user: %w", err)
	}
	wu, err := s.buildUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	assertion, session, err := s.rp.BeginLogin(wu, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin login: %w", err)
	}
	sessionID, err = s.saveSession(ctx, "login", userID, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// BeginDiscoverableLogin starts a usernameless ("passkey autofill") login
// ceremony: the browser lets the user pick from any resident credential
// registered for this Relying Party without the caller specifying who is
// logging in beforehand. This is the flow behind the "Sign in with a
// passkey" button.
func (s *Strategy) BeginDiscoverableLogin(ctx context.Context, opts ...gowebauthn.LoginOption) (assertion *protocol.CredentialAssertion, sessionID string, err error) {
	assertion, session, err := s.rp.BeginDiscoverableLogin(opts...)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin discoverable login: %w", err)
	}
	sessionID, err = s.saveSession(ctx, "login", "", session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// FinishLogin completes a login ceremony started by either BeginLogin or
// BeginDiscoverableLogin. r must carry the raw JSON body produced by the
// browser's navigator.credentials.get() response
// (PublicKeyCredential.toJSON()).
//
// On success the authenticator's signature counter is persisted back to the
// CredentialStore; a counter that fails to advance across two logins is how
// a cloned authenticator is detected, so hosts wanting that defence should
// watch for a shrinking/stalled counter in their CredentialStore.Update
// implementation.
func (s *Strategy) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*multipass.Principal, error) {
	userID, session, err := s.consumeSession(ctx, "login", sessionID)
	if err != nil {
		return nil, err
	}

	// gowebauthn.ValidatePasskeyLogin (used for discoverable logins) requires
	// SessionData.UserID to be empty, while ValidateLogin (non-discoverable)
	// requires it to match the supplied user. The two ceremonies are
	// therefore not interchangeable and must be routed based on which Begin*
	// call started this session — tracked by our own userID, which mirrors
	// gowebauthn's session.UserID 1:1 (see BeginLogin / BeginDiscoverableLogin).
	var (
		cred       *gowebauthn.Credential
		resolvedID string
	)
	if userID != "" {
		u, err := s.users.GetByID(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("webauthn: load user: %w", err)
		}
		wu, err := s.buildUser(ctx, u)
		if err != nil {
			return nil, err
		}
		if cred, err = s.rp.FinishLogin(wu, *session, r); err != nil {
			return nil, fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, err)
		}
		resolvedID = userID
	} else {
		handler := func(_ []byte, userHandle []byte) (gowebauthn.User, error) {
			u, err := s.users.GetByID(ctx, string(userHandle))
			if err != nil {
				return nil, err
			}
			return s.buildUser(ctx, u)
		}
		validatedUser, c, err := s.rp.FinishPasskeyLogin(handler, *session, r)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", multipass.ErrTokenInvalid, err)
		}
		cred = c
		if wu, ok := validatedUser.(*webauthnUser); ok {
			resolvedID = wu.id
		}
	}
	if resolvedID == "" {
		return nil, multipass.ErrTokenInvalid
	}

	s.bumpCounter(ctx, resolvedID, cred)

	u, err := s.users.GetByID(ctx, resolvedID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: load user: %w", err)
	}

	return &multipass.Principal{
		UserID:       u.ID,
		Email:        u.Email,
		Roles:        u.Roles,
		StrategyName: Name,
		TokenID:      base64.RawURLEncoding.EncodeToString(cred.ID),
		IssuedAt:     s.clock.Now(),
	}, nil
}

// bumpCounter persists the authenticator's post-verification state (signature
// counter, clone-warning flag, ...) without disturbing the caller-supplied
// Name/CreatedAt fields already on record.
func (s *Strategy) bumpCounter(ctx context.Context, userID string, cred *gowebauthn.Credential) {
	data, err := json.Marshal(cred)
	if err != nil {
		return
	}
	name, created := "", s.clock.Now()
	if existing, err := s.creds.Get(ctx, cred.ID); err == nil && existing != nil {
		name, created = existing.Name, existing.CreatedAt
	}
	_ = s.creds.Update(ctx, store.WebAuthnCredential{
		ID:        cred.ID,
		UserID:    userID,
		Name:      name,
		Data:      data,
		CreatedAt: created,
	})
}

// saveSession stores WebAuthn SessionData under a fresh random id, reusing
// store.OTPStore's atomic delete-on-read semantics for the matching
// consumeSession call.
func (s *Strategy) saveSession(ctx context.Context, kind, userID string, session *gowebauthn.SessionData) (string, error) {
	blob, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("webauthn: marshal session: %w", err)
	}
	id, err := multipass.DefaultIDGen().NewID()
	if err != nil {
		return "", fmt.Errorf("webauthn: gen session id: %w", err)
	}
	if err := s.otp.Save(ctx, id, store.OTPPayload{
		UserID:  userID,
		Purpose: challengePurpose + ":" + kind,
		Extra:   map[string]any{"session": string(blob)},
	}, s.ttl); err != nil {
		return "", fmt.Errorf("webauthn: save session: %w", err)
	}
	return id, nil
}

func (s *Strategy) consumeSession(ctx context.Context, kind, sessionID string) (userID string, session *gowebauthn.SessionData, err error) {
	if sessionID == "" {
		return "", nil, multipass.ErrTokenInvalid
	}
	payload, err := s.otp.Consume(ctx, sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", nil, multipass.ErrTokenExpired
		}
		return "", nil, fmt.Errorf("webauthn: consume session: %w", err)
	}
	if payload.Purpose != challengePurpose+":"+kind {
		return "", nil, multipass.ErrTokenInvalid
	}
	blob, _ := payload.Extra["session"].(string)
	var sess gowebauthn.SessionData
	if err := json.Unmarshal([]byte(blob), &sess); err != nil {
		return "", nil, fmt.Errorf("webauthn: unmarshal session: %w", err)
	}
	return payload.UserID, &sess, nil
}

// buildUser adapts a multipass.User plus its persisted credentials into the
// gowebauthn.User shape the library needs to run a ceremony.
func (s *Strategy) buildUser(ctx context.Context, u *multipass.User) (*webauthnUser, error) {
	recs, err := s.creds.ListByUser(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: list credentials: %w", err)
	}
	creds := make([]gowebauthn.Credential, 0, len(recs))
	for _, rec := range recs {
		var c gowebauthn.Credential
		if err := json.Unmarshal(rec.Data, &c); err != nil {
			continue
		}
		creds = append(creds, c)
	}
	name := u.Email
	if name == "" {
		name = u.ID
	}
	return &webauthnUser{id: u.ID, name: name, displayName: name, creds: creds}, nil
}

// webauthnUser adapts a multipass user identity to gowebauthn.User.
type webauthnUser struct {
	id          string
	name        string
	displayName string
	creds       []gowebauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                           { return []byte(u.id) }
func (u *webauthnUser) WebAuthnName() string                         { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                  { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

var (
	_ multipass.Strategy      = (*Strategy)(nil)
	_ multipass.RevokeAllable = (*Strategy)(nil)
	_ gowebauthn.User         = (*webauthnUser)(nil)
)
