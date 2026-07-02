// Example: fully passwordless login via magic links (strategy/magiclink),
// issuing a JWT once the link is clicked.
//
// There is no password anywhere in this example: /login/request creates the
// user on first sight (identified by email alone) and "sends" a one-time
// link. In place of a real mail provider, the link is printed to stdout —
// copy it from the server log into your browser (or curl it) to complete
// the login.
//
// Endpoints:
//
//	POST /login/request  {email}                  -> 202 (link printed to stdout)
//	GET  /login/verify?token=...                   -> {access, refresh}
//	GET  /me              Authorization: Bearer ... -> {user_id, email, roles}
//
// Run:
//
//	go run ./examples/magiclink
//
// Try it:
//
//	curl -X POST localhost:8080/login/request -d '{"email":"alice@example.com"}'
//	# copy the printed link/token, then:
//	curl 'localhost:8080/login/verify?token=<token>'
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
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/jwt"
	"github.com/yurii-bondar/multipass/strategy/magiclink"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

const linkPrefix = "http://localhost:8080/login/verify?token="

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

	sender := magiclink.SenderFunc(func(_ context.Context, to, payload string) error {
		log.Printf("[magic link] sending to %s: %s", to, payload)
		return nil
	})
	linkStrat, err := magiclink.New(memory.NewOTPStore(), sender,
		magiclink.WithTTL(10*time.Minute),
		magiclink.WithURLPrefix(linkPrefix),
		magiclink.WithPurpose("login"),
	)
	if err != nil {
		log.Fatal(err)
	}

	svc := multipass.New(users)
	svc.Register(jwtStrat)
	svc.Register(linkStrat)

	mw := transport.New(svc, jwtStrat.Name(), extract.BearerFromHeader)

	mux := http.NewServeMux()
	mux.HandleFunc("/login/request", requestHandler(svc, users))
	mux.HandleFunc("/login/verify", verifyHandler(svc))
	mux.Handle("/me", mw.Handler(http.HandlerFunc(meHandler)))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

// requestHandler looks the user up by email, creating a fresh (passwordless)
// account on first sight, then asks the magiclink strategy to mint and
// "send" a one-time code.
func requestHandler(svc *multipass.Service, users *memUsers) http.HandlerFunc {
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

		if _, err := svc.Issue(r.Context(), magiclink.Name, multipass.Principal{
			UserID: u.ID, Email: u.Email,
		}); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

// verifyHandler consumes the one-time code (single-use — a second attempt
// with the same token fails) and, on success, issues a JWT for the resolved
// user.
func verifyHandler(svc *multipass.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token is required", 400)
			return
		}
		principal, err := svc.Verify(r.Context(), magiclink.Name, token)
		if err != nil {
			http.Error(w, "invalid or expired link", 401)
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
