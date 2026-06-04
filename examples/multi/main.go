// Example: a single Service that multiplexes multiple strategies on the
// same server.
//
//   - /api/*  is JWT-protected (Authorization: Bearer ...)
//   - /web/*  is session-cookie protected
//   - /m2m/*  is API-key protected (X-API-Key)
//
// The same UserRepository is shared across all of them: there is one Login
// flow (local strategy) and the application picks which credential type to
// hand back based on the route.
//
// Run:
//
//	go run ./examples/multi
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/password"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/apikey"
	"github.com/yurii-bondar/multipass/strategy/jwt"
	"github.com/yurii-bondar/multipass/strategy/local"
	"github.com/yurii-bondar/multipass/strategy/session"
	"github.com/yurii-bondar/multipass/transport/cookie"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

func main() {
	users := newMemUsers()
	hasher := password.NewHasher()

	// JWT
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwtStrat, _ := jwt.New(
		jwt.StaticKeyProvider{K: jwt.Key{KID: "k1", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}},
		jwt.WithIssuer("multi"),
		jwt.WithAccessTTL(15*time.Minute),
		jwt.WithRefreshStore(memory.NewRefreshStore()),
		jwt.WithBlacklist(memory.NewBlacklist()),
	)

	// Session
	sessStrat, _ := session.New(memory.NewSessionStore(),
		session.WithAbsoluteTTL(24*time.Hour),
		session.WithIdleTimeout(30*time.Minute),
	)

	// API keys
	keyStrat, _ := apikey.New(newMemKeyStore(),
		apikey.WithPepper([]byte("0123456789abcdef0123456789abcdef")),
		apikey.WithPrefix("sk"),
		apikey.WithEnv("test"),
	)

	// Local (verifier only)
	localStrat := local.New(users, hasher)

	svc := multipass.New(users)
	svc.Register(jwtStrat)
	svc.Register(sessStrat)
	svc.Register(keyStrat)
	svc.Register(localStrat)

	cookies := cookie.New("session")
	cookies.Secure = false
	cookies.UseHostPrefix = false

	mwAPI := transport.New(svc, jwt.Name, extract.BearerFromHeader)
	mwWeb := transport.New(svc, session.Name, extract.TokenFromCookie(cookies.CookieName()))
	mwM2M := transport.New(svc, apikey.Name, extract.APIKeyFromHeader)

	mux := http.NewServeMux()

	mux.HandleFunc("/signup", signup(users, hasher))

	// API: returns Bearer access+refresh
	mux.HandleFunc("/api/login", apiLogin(svc))
	mux.Handle("/api/me", mwAPI.Handler(http.HandlerFunc(meHandler)))

	// Web: sets cookie
	mux.HandleFunc("/web/login", webLogin(svc, cookies))
	mux.Handle("/web/me", mwWeb.Handler(http.HandlerFunc(meHandler)))

	// M2M: bootstrap key creation by an authenticated API user
	mux.Handle("/m2m/keys", mwAPI.Handler(http.HandlerFunc(createKey(svc))))
	mux.Handle("/m2m/me", mwM2M.Handler(http.HandlerFunc(meHandler)))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

// ----- handlers ------------------------------------------------------------

func signup(repo multipass.UserRepository, h *password.Hasher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		hash, _ := h.Hash(body.Password)
		_ = repo.Create(r.Context(), &multipass.User{
			ID: uuid.NewString(), Email: body.Email, PasswordHash: hash,
		})
		w.WriteHeader(http.StatusCreated)
	}
}

func apiLogin(svc *multipass.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		creds, err := svc.Login(r.Context(), local.Name, jwt.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(creds)
	}
}

func webLogin(svc *multipass.Service, c *cookie.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		creds, err := svc.Login(r.Context(), local.Name, session.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid", 401)
			return
		}
		c.Set(w, creds.Access, time.Until(creds.AccessExpiry))
		w.WriteHeader(http.StatusNoContent)
	}
}

func createKey(svc *multipass.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := transport.MustFromContext(r.Context())
		creds, err := svc.Issue(r.Context(), apikey.Name, *p)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"key": creds.Access})
	}
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	p := transport.MustFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

// ----- tiny in-memory adapters --------------------------------------------

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
		return fmt.Errorf("exists")
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

// memKeyStore is an in-memory KeyStore for the API-key strategy.
type memKeyStore struct {
	mu   sync.Mutex
	rows map[string]*apikey.Record
}

func newMemKeyStore() *memKeyStore { return &memKeyStore{rows: map[string]*apikey.Record{}} }

func (s *memKeyStore) Save(_ context.Context, r apikey.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := r
	s.rows[r.ID] = &cp
	return nil
}
func (s *memKeyStore) FindByID(_ context.Context, id string) (*apikey.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok {
		c := *r
		return &c, nil
	}
	return nil, fmt.Errorf("not found")
}
func (s *memKeyStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[id]; ok {
		r.Revoked = true
	}
	return nil
}
func (s *memKeyStore) RevokeAllForUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.UserID == userID {
			r.Revoked = true
		}
	}
	return nil
}
