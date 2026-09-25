// Example: Passkey (FIDO2/WebAuthn) registration and login, backed by
// strategy/webauthn, with a JWT issued once the ceremony succeeds.
//
// This is the one example in this repo you drive from a real browser, not
// curl: WebAuthn ceremonies happen through navigator.credentials, which only
// exists in a browser. Point Chrome/Safari/Edge/Firefox at
// http://localhost:8080 — WebAuthn treats "localhost" as a secure context,
// so plain http works for local development, no TLS setup required.
//
// From the page you can:
//   - register a passkey (Touch ID / Windows Hello / a phone via the QR
//     "hybrid" flow / a USB security key — whatever your OS offers),
//   - log in with that passkey, either by typing the email first or
//     usernameless (the browser lets you pick from any resident passkey for
//     this site),
//   - call GET /me with the resulting JWT to see the authenticated Principal.
//
// Endpoints:
//
//	GET  /                          the demo page (open this first)
//	POST /register/start   {email}  -> {options, session_id}
//	POST /register/finish?session=  <raw PublicKeyCredential JSON>          -> 204
//	GET  /login/start[?email=]      -> {options, session_id}
//	POST /login/finish?session=     <raw PublicKeyCredential JSON>          -> {access, refresh}
//	GET  /me                Authorization: Bearer ...                       -> {user_id, email, roles}
//
// Run:
//
//	go run ./examples/webauthn
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/jwt"
	passkey "github.com/yurii-bondar/multipass/strategy/webauthn"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

//go:embed index.html
var indexHTML embed.FS

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	users := newMemUsers()

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

	passkeyStrat, err := passkey.New(
		&gowebauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "multipass Passkey demo",
			RPOrigins:     []string{"http://localhost:8080"},
		},
		users,
		memory.NewCredentialStore(),
		memory.NewOTPStore(),
	)
	if err != nil {
		log.Fatal(err)
	}

	svc := multipass.New(users)
	svc.Register(jwtStrat)
	svc.Register(passkeyStrat)

	mw := transport.New(svc, jwtStrat.Name(), extract.BearerFromHeader)

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler())
	mux.HandleFunc("/register/start", registerStart(users, passkeyStrat))
	mux.HandleFunc("/register/finish", registerFinish(passkeyStrat))
	mux.HandleFunc("/login/start", loginStart(users, passkeyStrat))
	mux.HandleFunc("/login/finish", loginFinish(svc, passkeyStrat))
	mux.Handle("/me", mw.Handler(http.HandlerFunc(meHandler)))

	log.Println("listening on :8080 — open http://localhost:8080 in a browser")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func indexHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		b, _ := indexHTML.ReadFile("index.html")
		_, _ = w.Write(b)
	}
}

// registerStart resolves (or creates, on first sight) the user by email and
// starts a registration ceremony for a resident ("discoverable") key, i.e. a
// real passkey rather than a plain non-resident FIDO2 credential.
func registerStart(users *memUsers, strat *passkey.Strategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email == "" {
			http.Error(w, "email is required", 400)
			return
		}

		u, err := users.GetByEmail(r.Context(), body.Email)
		if errors.Is(err, multipass.ErrUserNotFound) {
			u = &multipass.User{ID: uuid.NewString(), Email: body.Email, Roles: []string{"member"}}
			if err := users.Create(r.Context(), u); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		creation, sessionID, err := strat.BeginRegistration(r.Context(), u,
			gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"options": creation, "session_id": sessionID})
	}
}

func registerFinish(strat *passkey.Strategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session")
		if sessionID == "" {
			http.Error(w, "session is required", 400)
			return
		}
		if _, err := strat.FinishRegistration(r.Context(), sessionID, "browser passkey", r); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// loginStart starts a login ceremony. With ?email= it's a regular
// (non-discoverable) login for a known user; without it, it's usernameless —
// the browser prompts the user to pick from any resident passkey.
func loginStart(users *memUsers, strat *passkey.Strategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")

		var (
			assertion *protocol.CredentialAssertion
			sessionID string
			err       error
		)
		if email == "" {
			assertion, sessionID, err = strat.BeginDiscoverableLogin(r.Context())
		} else {
			u, gerr := users.GetByEmail(r.Context(), email)
			if gerr != nil {
				http.Error(w, "unknown user", 404)
				return
			}
			assertion, sessionID, err = strat.BeginLogin(r.Context(), u.ID)
		}
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"options": assertion, "session_id": sessionID})
	}
}

func loginFinish(svc *multipass.Service, strat *passkey.Strategy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session")
		if sessionID == "" {
			http.Error(w, "session is required", 400)
			return
		}
		principal, err := strat.FinishLogin(r.Context(), sessionID, r)
		if err != nil {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		creds, err := svc.Issue(r.Context(), jwt.Name, *principal)
		if err != nil {
			http.Error(w, err.Error(), 500)
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
