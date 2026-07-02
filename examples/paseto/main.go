// Example: a stdlib net/http server protected by multipass's PASETO strategy
// (v4.public — Ed25519-signed, plaintext payload; no "alg" field, so there is
// no algorithm-confusion attack surface the way there is with JWT).
//
// Endpoints:
//
//	POST /signup    {email, password}             -> 200
//	POST /login     {email, password}             -> {access, refresh}
//	POST /refresh   {refresh}                     -> {access, refresh}
//	POST /logout    Authorization: Bearer ...     -> 204
//	GET  /me        Authorization: Bearer ...     -> {user_id, email, roles}
//
// Run:
//
//	go run ./examples/paseto
//
// The user repository and refresh store are in-memory: state is lost on
// restart. Wire your own implementations in production.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	pst "aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/password"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/local"
	"github.com/yurii-bondar/multipass/strategy/paseto"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

func main() {
	secret := pst.NewV4AsymmetricSecretKey()
	public := secret.Public()

	users := newMemUsers()
	hasher := password.NewHasher()

	pasetoStrat, err := paseto.New(
		paseto.ModePublic,
		paseto.Keys{Secret: &secret, Public: &public},
		paseto.WithIssuer("example"),
		paseto.WithAudience("example.api"),
		paseto.WithAccessTTL(15*time.Minute),
		paseto.WithRefreshTTL(30*24*time.Hour),
		paseto.WithBlacklist(memory.NewBlacklist()),
		paseto.WithRefreshStore(memory.NewRefreshStore()),
	)
	if err != nil {
		log.Fatal(err)
	}
	localStrat := local.New(users, hasher)

	svc := multipass.New(users)
	svc.Register(pasetoStrat)
	svc.Register(localStrat)

	mw := transport.New(svc, pasetoStrat.Name(), extract.BearerFromHeader)

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signupHandler(users, hasher))
	mux.HandleFunc("/login", loginHandler(svc))
	mux.HandleFunc("/refresh", refreshHandler(svc, pasetoStrat.Name()))
	mux.HandleFunc("/logout", logoutHandler(svc, pasetoStrat.Name()))
	mux.Handle("/me", mw.Handler(http.HandlerFunc(meHandler)))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

func signupHandler(repo multipass.UserRepository, h *password.Hasher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email, Password string
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		hash, err := h.Hash(body.Password)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		u := &multipass.User{
			ID:           uuid.NewString(),
			Email:        body.Email,
			PasswordHash: hash,
			Roles:        []string{"member"},
		}
		if err := repo.Create(r.Context(), u); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
}

func loginHandler(svc *multipass.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Email, Password string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		creds, err := svc.Login(r.Context(), local.Name, paseto.Name, body.Email, body.Password)
		if err != nil {
			http.Error(w, "invalid credentials", 401)
			return
		}
		writeJSON(w, creds)
	}
}

func refreshHandler(svc *multipass.Service, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Refresh string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		creds, err := svc.Refresh(r.Context(), name, body.Refresh)
		if err != nil {
			if errors.Is(err, multipass.ErrReuseDetected) {
				http.Error(w, "session compromised — log in again", 401)
				return
			}
			http.Error(w, err.Error(), 401)
			return
		}
		writeJSON(w, creds)
	}
}

func logoutHandler(svc *multipass.Service, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := extract.BearerFromHeader(r)
		_ = svc.Revoke(r.Context(), name, raw)
		w.WriteHeader(http.StatusNoContent)
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

// ---- in-memory user repository (same shape as in examples/jwt) ----------

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
