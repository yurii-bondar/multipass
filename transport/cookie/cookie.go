// Package cookie offers safe defaults for cookie-based credential
// transport. Callers can construct a Manager once and use it from every
// handler; or build cookies directly with NewSecure when more control is
// needed.
//
// Defaults:
//
//   - HttpOnly: true (cookie is invisible to JavaScript)
//   - Secure: true (cookie is only sent over TLS)
//   - SameSite: Lax (sane CSRF defaults; switch to Strict for high-value
//     cookies and to None for cross-site SPA scenarios — but None requires
//     Secure=true and __Host- prefix is incompatible with it)
//   - Path: "/"
//
// Host prefix
//
// When UseHostPrefix is enabled the cookie name is automatically prepended
// with "__Host-", which forbids the cookie from being set with a Domain
// attribute and pins it to the exact host. This protects against subdomain
// take-overs — recommended for any session/token cookie.
package cookie

import (
	"net/http"
	"strings"
	"time"
)

// Manager is the high-level builder of credential cookies.
type Manager struct {
	Name          string        // logical cookie name, "session" / "auth" / …
	Path          string        // default "/"
	Domain        string        // empty == host-only (preferred)
	SameSite      http.SameSite // default Lax
	Secure        bool          // default true
	HttpOnly      bool          // default true
	UseHostPrefix bool          // default true: "__Host-" + Name
}

// New constructs a Manager with safe defaults.
func New(name string) *Manager {
	return &Manager{
		Name:          name,
		Path:          "/",
		SameSite:      http.SameSiteLaxMode,
		Secure:        true,
		HttpOnly:      true,
		UseHostPrefix: true,
	}
}

// CookieName returns the actual cookie name including the __Host- prefix
// when applicable.
func (m *Manager) CookieName() string {
	if m.UseHostPrefix && m.Domain == "" && (m.Path == "" || m.Path == "/") {
		return "__Host-" + strings.TrimPrefix(m.Name, "__Host-")
	}
	return m.Name
}

// Set writes the credential cookie to w. ttl <= 0 makes the cookie a session
// cookie (cleared on browser close).
func (m *Manager) Set(w http.ResponseWriter, value string, ttl time.Duration) {
	http.SetCookie(w, m.build(value, ttl))
}

// Clear writes a deletion cookie that the browser drops on the next render.
func (m *Manager) Clear(w http.ResponseWriter) {
	c := m.build("", -time.Hour)
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0)
	http.SetCookie(w, c)
}

// Read returns the cookie value or "" if not present.
func (m *Manager) Read(r *http.Request) string {
	c, err := r.Cookie(m.CookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func (m *Manager) build(value string, ttl time.Duration) *http.Cookie {
	c := &http.Cookie{
		Name:     m.CookieName(),
		Value:    value,
		Path:     m.Path,
		Domain:   m.Domain,
		Secure:   m.Secure,
		HttpOnly: m.HttpOnly,
		SameSite: m.SameSite,
	}
	if c.Path == "" {
		c.Path = "/"
	}
	// __Host- forbids Domain — strip it to keep the prefix valid.
	if strings.HasPrefix(c.Name, "__Host-") {
		c.Domain = ""
		c.Path = "/"
		c.Secure = true
	}
	if ttl > 0 {
		c.MaxAge = int(ttl.Seconds())
		c.Expires = time.Now().Add(ttl)
	}
	return c
}

// NewSecure is a one-shot helper for callers that don't want a Manager.
//
// Returns a cookie with HttpOnly=true, Secure=true, SameSite=Lax, Path="/",
// and the __Host- prefix when no domain/path override is present.
func NewSecure(name, value string, ttl time.Duration) *http.Cookie {
	return New(name).build(value, ttl)
}
