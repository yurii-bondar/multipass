package multipass_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yurii-bondar/multipass"
)

// fakeStrategy is a minimal multipass.Strategy implementation. By default it
// satisfies only the base contract; the optional flags promote it to also
// implementing Refreshable / Authenticator / RevokeAllable.
type fakeStrategy struct {
	name      string
	issued    multipass.Credentials
	verifyP   *multipass.Principal
	verifyErr error
	revoked   string

	revokedAllFor string
	refreshed     multipass.Credentials
}

func (f *fakeStrategy) Name() string { return f.name }
func (f *fakeStrategy) Issue(_ context.Context, p multipass.Principal) (multipass.Credentials, error) {
	c := f.issued
	c.Subject = p.UserID
	return c, nil
}
func (f *fakeStrategy) Verify(_ context.Context, _ string) (*multipass.Principal, error) {
	return f.verifyP, f.verifyErr
}
func (f *fakeStrategy) Revoke(_ context.Context, raw string) error { f.revoked = raw; return nil }

// Optional capability promotion.
type authStrategy struct{ *fakeStrategy }

func (a authStrategy) Authenticate(_ context.Context, id, _ string) (*multipass.Principal, error) {
	return &multipass.Principal{UserID: "u-" + id}, nil
}

type refreshableStrategy struct{ *fakeStrategy }

func (r refreshableStrategy) Refresh(_ context.Context, _ string) (multipass.Credentials, error) {
	return r.refreshed, nil
}

type revokeAllStrategy struct{ *fakeStrategy }

func (r revokeAllStrategy) RevokeAllForUser(_ context.Context, userID string) error {
	r.revokedAllFor = userID
	return nil
}

func TestService_RegisterAndStrategy(t *testing.T) {
	svc := multipass.New(nil)
	svc.Register(&fakeStrategy{name: "x"})
	if _, err := svc.Strategy("x"); err != nil {
		t.Fatalf("Strategy: %v", err)
	}
	if _, err := svc.Strategy("missing"); !errors.Is(err, multipass.ErrUnknownStrategy) {
		t.Fatalf("expected ErrUnknownStrategy, got %v", err)
	}
}

func TestService_RegisterPanics(t *testing.T) {
	svc := multipass.New(nil)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate Register")
		}
	}()
	svc.Register(&fakeStrategy{name: "x"})
	svc.Register(&fakeStrategy{name: "x"})
}

func TestService_Login_RoutesAuthenticatorThenIssue(t *testing.T) {
	svc := multipass.New(nil)
	loc := authStrategy{fakeStrategy: &fakeStrategy{name: "local"}}
	tok := &fakeStrategy{name: "tok", issued: multipass.Credentials{Access: "ok"}}
	svc.Register(loc)
	svc.Register(tok)

	creds, err := svc.Login(context.Background(), "local", "tok", "alice", "pwd")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Access != "ok" || creds.Subject != "u-alice" {
		t.Errorf("unexpected creds: %+v", creds)
	}
}

func TestService_Refresh_UnsupportedStrategy(t *testing.T) {
	svc := multipass.New(nil)
	svc.Register(&fakeStrategy{name: "session"}) // base only
	if _, err := svc.Refresh(context.Background(), "session", "anything"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestService_Refresh_Routes(t *testing.T) {
	svc := multipass.New(nil)
	rs := refreshableStrategy{fakeStrategy: &fakeStrategy{name: "tok"}}
	rs.refreshed = multipass.Credentials{Access: "new"}
	svc.Register(rs)
	creds, err := svc.Refresh(context.Background(), "tok", "old")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Access != "new" {
		t.Errorf("creds.Access = %q", creds.Access)
	}
}

func TestService_RevokeAll_Routes(t *testing.T) {
	svc := multipass.New(nil)
	rev := revokeAllStrategy{fakeStrategy: &fakeStrategy{name: "session"}}
	svc.Register(rev)
	if err := svc.RevokeAllForUser(context.Background(), "session", "u1"); err != nil {
		t.Fatal(err)
	}
	if rev.revokedAllFor != "u1" {
		t.Errorf("RevokeAllForUser did not propagate userID: got %q, want %q",
			rev.revokedAllFor, "u1")
	}
}

func TestService_Verify_PassesThrough(t *testing.T) {
	svc := multipass.New(nil)
	svc.Register(&fakeStrategy{name: "tok", verifyP: &multipass.Principal{UserID: "u1"}})
	p, err := svc.Verify(context.Background(), "tok", "any")
	if err != nil {
		t.Fatal(err)
	}
	if p.UserID != "u1" {
		t.Errorf("got %+v", p)
	}
}
