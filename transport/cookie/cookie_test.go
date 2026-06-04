package cookie

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	m := New("session")
	if !m.Secure || !m.HttpOnly {
		t.Errorf("HttpOnly/Secure should default to true")
	}
	if m.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite default should be Lax")
	}
	if m.CookieName() != "__Host-session" {
		t.Errorf("CookieName: %q", m.CookieName())
	}
}

func TestSet_HasFlags(t *testing.T) {
	m := New("auth")
	rr := httptest.NewRecorder()
	m.Set(rr, "v", time.Minute)
	header := rr.Header().Get("Set-Cookie")
	for _, expect := range []string{"__Host-auth=v", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(header, expect) {
			t.Errorf("Set-Cookie missing %q: %s", expect, header)
		}
	}
}

func TestClear(t *testing.T) {
	m := New("auth")
	rr := httptest.NewRecorder()
	m.Clear(rr)
	header := rr.Header().Get("Set-Cookie")
	if !strings.Contains(header, "Max-Age=0") {
		t.Errorf("clear should set Max-Age=0, got %s", header)
	}
}

func TestHostPrefix_DroppedWhenDomainSet(t *testing.T) {
	m := New("auth")
	m.Domain = "example.com"
	if strings.HasPrefix(m.CookieName(), "__Host-") {
		t.Errorf("__Host- must not be used when Domain is set: %q", m.CookieName())
	}
}

func TestRead(t *testing.T) {
	m := New("auth")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-auth", Value: "value"})
	if v := m.Read(r); v != "value" {
		t.Errorf("Read got %q", v)
	}
}
