// Package extract provides framework-agnostic helpers for pulling raw
// credentials out of an *http.Request.
//
// They are intentionally small and stateless. The package depends only on
// net/http; it does NOT import multipass itself, so it can be reused outside
// the library.
package extract

import (
	"net/http"
	"strings"
)

// Extractor pulls a credential string out of an HTTP request. Returning ""
// means "no credential present in this place"; the caller decides whether
// that should yield 401 or fall through to another extractor.
type Extractor func(r *http.Request) string

// BearerFromHeader returns the value after "Bearer " in the Authorization
// header. Comparison is case-insensitive on the scheme.
func BearerFromHeader(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// APIKeyFromHeader checks both the X-API-Key header and the Authorization
// "ApiKey ..." scheme. Returns the first non-empty match.
func APIKeyFromHeader(r *http.Request) string {
	if v := r.Header.Get("X-API-Key"); v != "" {
		return strings.TrimSpace(v)
	}
	h := r.Header.Get("Authorization")
	const prefix = "apikey "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// TokenFromCookie returns the value of the named cookie or "".
func TokenFromCookie(name string) Extractor {
	return func(r *http.Request) string {
		c, err := r.Cookie(name)
		if err != nil {
			return ""
		}
		return c.Value
	}
}

// TokenFromQuery returns the value of the named query parameter. Use with
// care: tokens in URLs leak into logs and Referer headers.
func TokenFromQuery(name string) Extractor {
	return func(r *http.Request) string {
		return strings.TrimSpace(r.URL.Query().Get(name))
	}
}

// First returns the first non-empty result among the supplied extractors.
// Convenient when an endpoint accepts the same credential via multiple
// transports (e.g. cookie OR Authorization header).
func First(exs ...Extractor) Extractor {
	return func(r *http.Request) string {
		for _, e := range exs {
			if v := e(r); v != "" {
				return v
			}
		}
		return ""
	}
}
