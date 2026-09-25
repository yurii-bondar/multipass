// Example: cookie-based session authentication on stdlib net/http.
//
// Compared with the JWT example, this one stores no state in the client at
// all: the cookie value is an opaque random id; everything about the user
// lives in the SessionStore (memory in this demo, swap for Redis in prod).
//
// Endpoints:
//
//	POST /signup    {email, password}
//	POST /login     {email, password}    sets cookie
//	POST /logout                          deletes cookie
//	GET  /me                              reads cookie
//
// Run:
//
//	go run ./examples/session
package main

import (
	"context"
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
	"github.com/yurii-bondar/multipass/strategy/local"
	"github.com/yurii-bondar/multipass/strategy/session"
	"github.com/yurii-bondar/multipass/transport/cookie"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

func main() {
	users := newMemUsers()
	hasher := password.NewHasher()
	sessStore := memory.NewSessionStore()

	sessStrat, err := session.New(sessStore,
		session.WithAbsoluteTTL(24*time.Hour),
		session.WithIdleTimeout(30*time.Minute),
	)
	if err != nil {
		log.Fatal(err)
	}
	localStrat := local.New(users, hasher)

	svc := multipass.New(users)
	svc.Register(sessStrat)
	svc.Register(localStrat)

	cookies := cookie.New("session")
	// During local development you may need to disable Secure so cookies
	// flow over plain http://localhost. Don't do this in production.
	cookies.Secure = false
	cookies.UseHostPrefix = false

	mw := transport.New(svc, sessStrat.Name(), extract.First(
		extract.TokenFromCookie(cookies.CookieName()),
		extract.BearerFromHeader,
	))

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signup(users, hasher))
	mux.HandleFunc("/login", login(svc, cookies))
	mux.HandleFunc("/logout", logout(svc, sessStrat.Name(), cookies))
	mux.Handle("/me", mw.Handler(http.HandlerFunc(me)))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func signup(repo multipass.UserRepository, h *password.Hasher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		hash, _ := h.Hash(body.Password)
		_ = repo.Create(r.Context(), &multipass.User{
			ID: uuid.NewString(), Email: body.Email, PasswordHash: hash, Roles: []string{"member"},
		})
		w.WriteHeader(http.StatusCreated)
	}
}

func login(svc *multipass.Service, cookies *cookie.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		creds, err := svc.Login(r.Context(), local.Name, session.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		ttl := time.Until(creds.AccessExpiry)
		cookies.Set(w, creds.Access, ttl)
		w.WriteHeader(http.StatusNoContent)
	}
}

func logout(svc *multipass.Service, name string, cookies *cookie.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if v := cookies.Read(r); v != "" {
			_ = svc.Revoke(r.Context(), name, v)
		}
		cookies.Clear(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

func me(w http.ResponseWriter, r *http.Request) {
	p := transport.MustFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

// ---- in-memory user repository (same as in examples/jwt) ----------------

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
	if _, exists := m.byMail[u.Email]; exists {
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
