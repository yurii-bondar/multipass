// Package nethttp wires multipass into the standard library net/http server.
//
// It is the only transport adapter the library ships with: it stays under
// 200 LOC and serves as a template for any other framework (Gin, Fiber,
// Echo, Chi, …). For those, applications typically copy this file and
// translate ~10 lines.
//
// The middleware is built around a single Extractor, which is intentionally
// cheap to compose (extract.First lets the same handler accept "Bearer ..."
// AND a cookie, for instance).
package nethttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/transport/extract"
)

type ctxKey struct{}

// Middleware authenticates each request via the named strategy and injects
// the resulting Principal into the context. On failure it responds 401 with
// an empty body (you can inject your own error renderer via WithErrorWriter).
type Middleware struct {
	svc       *multipass.Service
	strategy  string
	extractor extract.Extractor

	onFailure func(w http.ResponseWriter, r *http.Request, err error)
}

// Option configures a Middleware.
type Option func(*Middleware)

// WithErrorWriter overrides the default 401 renderer.
func WithErrorWriter(fn func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(m *Middleware) { m.onFailure = fn }
}

// New builds a Middleware. extractor is required; pass extract.BearerFromHeader
// or extract.First(...) for compositions.
func New(svc *multipass.Service, strategy string, extractor extract.Extractor, opts ...Option) *Middleware {
	m := &Middleware{
		svc:       svc,
		strategy:  strategy,
		extractor: extractor,
		onFailure: defaultOnFailure,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Handler wraps next: requests with a valid credential see the Principal in
// context; everything else is rejected.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := m.extractor(r)
		if raw == "" {
			m.onFailure(w, r, multipass.ErrTokenInvalid)
			return
		}
		p, err := m.svc.Verify(r.Context(), m.strategy, raw)
		if err != nil {
			m.onFailure(w, r, err)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// HandlerFunc is the http.HandlerFunc-shaped adapter.
func (m *Middleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return m.Handler(next).ServeHTTP
}

// FromContext returns the authenticated Principal injected by the middleware.
// Returns (nil, false) if the request did not pass through the middleware.
func FromContext(ctx context.Context) (*multipass.Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*multipass.Principal)
	return p, ok
}

// MustFromContext is FromContext with a panic on missing value.
// Use only inside handlers behind the Middleware.
func MustFromContext(ctx context.Context) *multipass.Principal {
	p, ok := FromContext(ctx)
	if !ok {
		panic("multipass/transport/nethttp: no Principal in context")
	}
	return p
}

func defaultOnFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, multipass.ErrTokenExpired):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token expired"`)
	case errors.Is(err, multipass.ErrTokenRevoked):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token revoked"`)
	default:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
