package magiclink_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/strategy/magiclink"
)

type secretStore map[string]string

func (s secretStore) GetSecret(_ context.Context, userID string) (string, error) {
	if v, ok := s[userID]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

func TestTOTP_IssueAndVerify(t *testing.T) {
	store := secretStore{}
	s, err := magiclink.NewTOTP(store, magiclink.TOTPWithIssuer("AppX"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Email: "u@x.io"})
	if err != nil {
		t.Fatal(err)
	}
	store["u1"] = creds.Refresh

	code, err := magiclink.GenerateCode(creds.Refresh, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), "u1:"+code); err != nil {
		t.Fatalf("Verify good code: %v", err)
	}
	if _, err := s.Verify(context.Background(), "u1:000000"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected invalid for wrong code, got %v", err)
	}
}

func TestTOTP_UnknownUser(t *testing.T) {
	s, _ := magiclink.NewTOTP(secretStore{})
	if _, err := s.Verify(context.Background(), "ghost:123456"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestTOTP_MalformedRaw(t *testing.T) {
	s, _ := magiclink.NewTOTP(secretStore{})
	for _, raw := range []string{"", ":", "no-colon", ":code", "user:"} {
		if _, err := s.Verify(context.Background(), raw); !errors.Is(err, multipass.ErrTokenInvalid) {
			t.Errorf("raw %q expected ErrTokenInvalid, got %v", raw, err)
		}
	}
}
