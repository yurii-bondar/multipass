package paseto_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	pst "aidanwoods.dev/go-paseto"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/paseto"
)

func newLocal(t *testing.T) *paseto.Strategy {
	t.Helper()
	k := pst.NewV4SymmetricKey()
	s, err := paseto.New(paseto.ModeLocal, paseto.Keys{Symmetric: &k},
		paseto.WithIssuer("test"),
		paseto.WithAudience("api"),
		paseto.WithAccessTTL(time.Minute),
		paseto.WithRefreshTTL(time.Hour),
		paseto.WithBlacklist(memory.NewBlacklist()),
		paseto.WithRefreshStore(memory.NewRefreshStore()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newPublic(t *testing.T) *paseto.Strategy {
	t.Helper()
	priv := pst.NewV4AsymmetricSecretKey()
	pub := priv.Public()
	s, err := paseto.New(paseto.ModePublic, paseto.Keys{Secret: &priv, Public: &pub},
		paseto.WithIssuer("test"),
		paseto.WithAccessTTL(time.Minute),
		paseto.WithRefreshTTL(time.Hour),
		paseto.WithRefreshStore(memory.NewRefreshStore()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLocal_RoundTrip(t *testing.T) {
	s := newLocal(t)
	creds, err := s.Issue(context.Background(), multipass.Principal{
		UserID: "u1", Email: "a@b", Roles: []string{"admin", "member"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(creds.Access, "v4.local.") {
		t.Errorf("expected v4.local prefix, got %q", creds.Access[:12])
	}
	p, err := s.Verify(context.Background(), creds.Access)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "u1" || p.Email != "a@b" || len(p.Roles) != 2 {
		t.Errorf("principal: %+v", p)
	}
}

func TestPublic_RoundTrip(t *testing.T) {
	s := newPublic(t)
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(creds.Access, "v4.public.") {
		t.Errorf("expected v4.public prefix, got %q", creds.Access[:12])
	}
	if _, err := s.Verify(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
}

func TestVerify_RejectsRefreshAsAccess(t *testing.T) {
	s := newLocal(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), creds.Refresh); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	s := newLocal(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	tampered := creds.Access[:len(creds.Access)-2] + "00"
	if _, err := s.Verify(context.Background(), tampered); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	k := pst.NewV4SymmetricKey()
	s, err := paseto.New(paseto.ModeLocal, paseto.Keys{Symmetric: &k},
		paseto.WithAccessTTL(time.Millisecond),
		paseto.WithRefreshStore(memory.NewRefreshStore()),
	)
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	time.Sleep(20 * time.Millisecond)
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	s := newLocal(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Email: "a@b"})
	new1, err := s.Refresh(context.Background(), creds.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	if new1.Access == creds.Access || new1.Refresh == creds.Refresh {
		t.Fatal("rotation must change both tokens")
	}
	if _, err := s.Verify(context.Background(), new1.Access); err != nil {
		t.Fatalf("new access: %v", err)
	}
}

func TestRefresh_ReuseKillsFamily(t *testing.T) {
	s := newLocal(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	r1, err := s.Refresh(context.Background(), creds.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(context.Background(), creds.Refresh); !errors.Is(err, multipass.ErrReuseDetected) {
		t.Fatalf("expected reuse detection, got %v", err)
	}
	if _, err := s.Refresh(context.Background(), r1.Refresh); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("expected family kill, got %v", err)
	}
}

func TestRevoke_Blacklist(t *testing.T) {
	s := newLocal(t)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err := s.Revoke(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestPublicAndLocalNotInterchangeable(t *testing.T) {
	loc := newLocal(t)
	pub := newPublic(t)
	creds, _ := loc.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := pub.Verify(context.Background(), creds.Access); err == nil {
		t.Fatal("v4.local token must not parse as v4.public")
	}
}

type failingRefreshStore struct {
	*memory.RefreshStore
	killErr error
}

func (f *failingRefreshStore) KillFamily(context.Context, string) error { return f.killErr }

func TestRefresh_ReuseKillFailureIsReturned(t *testing.T) {
	boom := errors.New("store down")
	k := pst.NewV4SymmetricKey()
	s, err := paseto.New(paseto.ModeLocal, paseto.Keys{Symmetric: &k},
		paseto.WithRefreshStore(&failingRefreshStore{RefreshStore: memory.NewRefreshStore(), killErr: boom}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	creds, _ := s.Issue(ctx, multipass.Principal{UserID: "u1"})
	if _, err := s.Refresh(ctx, creds.Refresh); err != nil {
		t.Fatal(err)
	}
	_, err = s.Refresh(ctx, creds.Refresh)
	if !errors.Is(err, multipass.ErrReuseDetected) || !errors.Is(err, boom) {
		t.Fatalf("expected ErrReuseDetected joined with store error, got %v", err)
	}
}
