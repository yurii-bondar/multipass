// Example: TOTP-based two-factor authentication gating a JWT strategy, via
// multipass.RequireTwoFactor. The TOTP secret is a standard RFC 6238 secret,
// so any authenticator app works — Aegis, Google/Microsoft Authenticator,
// 1Password, ...
//
// This is the one decorator in the library: instead of a "2FA: true" flag
// bolted onto the jwt package, RequireTwoFactor wraps the already-registered
// jwt strategy so Issue additionally demands a TOTP code from users who have
// one enrolled — see two_factor.go in the repo root.
//
// Endpoints:
//
//	POST /signup      {email, password}                    -> 201
//	POST /2fa/enroll   {email, password}                    -> {otpauth_url, secret}
//	POST /login        {email, password, code?}             -> {access, refresh}
//	                    (code omitted + 2FA enrolled -> {"two_factor_required": true})
//	GET  /me           Authorization: Bearer ...             -> {user_id, email, roles}
//
// Run:
//
//	go run ./examples/twofactor
//
// Try it:
//
//	curl -X POST localhost:8080/signup     -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//	curl -X POST localhost:8080/2fa/enroll -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//	# paste "otpauth_url" into Aegis (Import via URI) or "secret" manually, then:
//	curl -X POST localhost:8080/login -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
//	# -> {"two_factor_required": true}
//	curl -X POST localhost:8080/login -d '{"email":"alice@example.com","password":"correct horse battery staple","code":"123456"}'
//	# -> {"Access": "...", ...}
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/password"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/jwt"
	"github.com/yurii-bondar/multipass/strategy/local"
	"github.com/yurii-bondar/multipass/strategy/magiclink"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	users := newMemUsers()
	hasher := password.NewHasher()

	jwtStrat, err := jwt.New(
		jwt.StaticKeyProvider{K: jwt.Key{KID: "k1", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}},
		jwt.WithIssuer("example"),
		jwt.WithAccessTTL(15*time.Minute),
		jwt.WithRefreshStore(memory.NewRefreshStore()),
		jwt.WithBlacklist(memory.NewBlacklist()),
	)
	if err != nil {
		log.Fatal(err)
	}
	localStrat := local.New(users, hasher)
	totpStrat, err := magiclink.NewTOTP(totpSecrets{users}, memory.NewTOTPGuard(), magiclink.TOTPWithIssuer("multipass demo"))
	if err != nil {
		log.Fatal(err)
	}

	// Only users who have enrolled (User.MFASecret != "") are actually gated;
	// everyone else logs in with just their password, unaffected.
	requirement := multipass.TwoFactorRequirementFunc(func(ctx context.Context, userID string) (bool, error) {
		u, err := users.GetByID(ctx, userID)
		if err != nil {
			return false, err
		}
		return u.MFASecret != "", nil
	})
	gatedJWT := multipass.RequireTwoFactor(jwtStrat, totpStrat, multipass.WithRequirement(requirement))

	svc := multipass.New(users)
	svc.Register(gatedJWT) // registers under jwtStrat.Name() — "jwt" — the gate is transparent
	svc.Register(localStrat)

	mw := transport.New(svc, jwt.Name, extract.BearerFromHeader)

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signupHandler(users, hasher))
	mux.HandleFunc("/2fa/enroll", enrollHandler(svc, users, totpStrat))
	mux.HandleFunc("/login", loginHandler(svc))
	mux.Handle("/me", mw.Handler(http.HandlerFunc(meHandler)))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func signupHandler(repo multipass.UserRepository, h *password.Hasher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		hash, err := h.Hash(body.Password)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		u := &multipass.User{ID: uuid.NewString(), Email: body.Email, PasswordHash: hash, Roles: []string{"member"}}
		if err := repo.Create(r.Context(), u); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

// enrollHandler re-verifies the password (enrolling 2FA is a sensitive
// change) then mints a fresh TOTP secret and persists it on the user record.
// creds.Access is the otpauth:// provisioning URL (turn it into a QR code
// with any generator, or paste it directly — Aegis supports "Import via
// URI"); creds.Refresh is the raw base32 secret for manual entry.
func enrollHandler(svc *multipass.Service, users *memUsers, totpStrat *magiclink.TOTPStrategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		principal, err := svc.Authenticate(r.Context(), local.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid credentials", 401)
			return
		}
		creds, err := totpStrat.Issue(r.Context(), *principal)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		users.SetMFASecret(principal.UserID, creds.Refresh)
		writeJSON(w, map[string]string{
			"otpauth_url": creds.Access,
			"secret":      creds.Refresh,
			"hint":        "scan otpauth_url as a QR code, or add `secret` manually in Aegis / Google Authenticator / 1Password",
		})
	}
}

// loginHandler authenticates the password first, then — only for users with
// 2FA enrolled — demands a TOTP code before Issue mints a JWT. The
// TOTPStrategy.Verify wire format is "<userID>:<code>", built here from the
// already-authenticated principal so the client only ever has to send the
// 6-digit code.
func loginHandler(svc *multipass.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password, Code string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		principal, err := svc.Authenticate(r.Context(), local.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid credentials", 401)
			return
		}
		if body.Code != "" {
			principal.Extra = map[string]any{"2fa_code": principal.UserID + ":" + body.Code}
		}

		creds, err := svc.Issue(r.Context(), jwt.Name, *principal)
		if err != nil {
			if errors.Is(err, multipass.ErrTwoFactorRequired) {
				writeJSON(w, map[string]bool{"two_factor_required": true})
				return
			}
			http.Error(w, "invalid credentials", 401)
			return
		}
		writeJSON(w, creds)
	}
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	p := transport.MustFromContext(r.Context())
	writeJSON(w, p)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// totpSecrets adapts memUsers to magiclink.TOTPSecretStore.
type totpSecrets struct{ users *memUsers }

func (t totpSecrets) GetSecret(ctx context.Context, userID string) (string, error) {
	u, err := t.users.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	return u.MFASecret, nil
}

// ---- in-memory user repository -------------------------------------------

type memUsers struct {
	mu     sync.Mutex
	byID   map[string]*multipass.User
	byMail map[string]string
}

func newMemUsers() *memUsers {
	return &memUsers{byID: map[string]*multipass.User{}, byMail: map[string]string{}}
}

func (m *memUsers) GetByID(_ context.Context, id string) (*multipass.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, multipass.ErrUserNotFound
}

func (m *memUsers) GetByEmail(_ context.Context, email string) (*multipass.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byMail[email]
	if !ok {
		return nil, multipass.ErrUserNotFound
	}
	c := *m.byID[id]
	return &c, nil
}

func (m *memUsers) Create(_ context.Context, u *multipass.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byMail[u.Email]; ok {
		return fmt.Errorf("user already exists")
	}
	cp := *u
	m.byID[u.ID] = &cp
	m.byMail[u.Email] = u.ID
	return nil
}

func (m *memUsers) UpdatePasswordHash(_ context.Context, id, hash string, ver int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.PasswordHash = hash
		u.PasswordVer = ver
	}
	return nil
}

func (m *memUsers) IncrementFailedLogin(_ context.Context, id string, lockUntil time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return 0, multipass.ErrUserNotFound
	}
	u.FailedLogins++
	if !lockUntil.IsZero() {
		u.LockedUntil = lockUntil
	}
	return u.FailedLogins, nil
}

func (m *memUsers) ResetFailedLogin(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.FailedLogins = 0
		u.LockedUntil = time.Time{}
	}
	return nil
}

// SetMFASecret persists a TOTP secret for userID. Not part of
// multipass.UserRepository — an application-specific enrollment step, wired
// here directly into the in-memory store for demo purposes.
func (m *memUsers) SetMFASecret(userID, secret string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[userID]; ok {
		u.MFASecret = secret
	}
}
