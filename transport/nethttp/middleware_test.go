package nethttp_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/jwt"
	"github.com/yurii-bondar/multipass/transport/extract"
	transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

// The middleware does not exercise UserRepository; we pass nil to multipass.New
// in these tests.

func TestMiddleware_Allows(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	js, err := jwt.New(jwt.StaticKeyProvider{K: jwt.Key{KID: "k", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}},
		jwt.WithRefreshStore(memory.NewRefreshStore()))
	if err != nil {
		t.Fatal(err)
	}
	svc := multipass.New(nil)
	svc.Register(js)

	creds, err := svc.Issue(context.Background(), js.Name(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}

	mw := transport.New(svc, js.Name(), extract.BearerFromHeader)
	called := false
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p := transport.MustFromContext(r.Context())
		if p.UserID != "u1" {
			t.Errorf("subject: %q", p.UserID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+creds.Access)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 + call, got %d / called=%v", rr.Code, called)
	}
}

func TestMiddleware_RejectsMissing(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	js, _ := jwt.New(jwt.StaticKeyProvider{K: jwt.Key{KID: "k", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}})
	svc := multipass.New(nil)
	svc.Register(js)
	mw := transport.New(svc, js.Name(), extract.BearerFromHeader)
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_RejectsBadToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	js, _ := jwt.New(jwt.StaticKeyProvider{K: jwt.Key{KID: "k", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}})
	svc := multipass.New(nil)
	svc.Register(js)
	mw := transport.New(svc, js.Name(), extract.BearerFromHeader)
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
