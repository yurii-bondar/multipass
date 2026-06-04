package extract

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerFromHeader(t *testing.T) {
	for _, tc := range []struct {
		header, want string
	}{
		{"Bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer xyz", "xyz"},
		{"BEARER  spaces ", "spaces"},
		{"Basic dXNlcjpwd2Q=", ""},
		{"", ""},
		{"Bearer", ""},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		if got := BearerFromHeader(r); got != tc.want {
			t.Errorf("BearerFromHeader(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestAPIKeyFromHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "sk_live_xx")
	if v := APIKeyFromHeader(r); v != "sk_live_xx" {
		t.Errorf("X-API-Key got %q", v)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Authorization", "ApiKey sk_test_42")
	if v := APIKeyFromHeader(r2); v != "sk_test_42" {
		t.Errorf("Authorization ApiKey got %q", v)
	}
}

func TestTokenFromCookie(t *testing.T) {
	ex := TokenFromCookie("session")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	if v := ex(r); v != "abc" {
		t.Errorf("cookie got %q", v)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if v := ex(r2); v != "" {
		t.Errorf("missing cookie should yield empty, got %q", v)
	}
}

func TestFirst(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer xyz")
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	ex := First(TokenFromCookie("session"), BearerFromHeader)
	if v := ex(r); v != "abc" {
		t.Errorf("First should pick cookie first, got %q", v)
	}
	ex2 := First(BearerFromHeader, TokenFromCookie("session"))
	if v := ex2(r); v != "xyz" {
		t.Errorf("First should pick bearer first, got %q", v)
	}
}
