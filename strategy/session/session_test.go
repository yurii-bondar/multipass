package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/session"
)

func newStrat(t *testing.T, opts ...session.Option) (*session.Strategy, *memory.SessionStore) {
	t.Helper()
	st := memory.NewSessionStore()
	s, err := session.New(st, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, st
}

func TestIssueVerifyRevoke(t *testing.T) {
	s, _ := newStrat(t, session.WithAbsoluteTTL(time.Minute))
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Roles: []string{"member"}})
	if err != nil {
		t.Fatal(err)
	}
	if creds.Access == "" || creds.TokenType != "Session" {
		t.Fatalf("creds: %+v", creds)
	}
	p, err := s.Verify(context.Background(), creds.Access)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "u1" || len(p.Roles) != 1 {
		t.Errorf("principal: %+v", p)
	}
	if err := s.Revoke(context.Background(), creds.Access); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid after revoke, got %v", err)
	}
}

func TestVerify_AbsoluteExpiry(t *testing.T) {
	s, _ := newStrat(t, session.WithAbsoluteTTL(20*time.Millisecond))
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	time.Sleep(40 * time.Millisecond)
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) && !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestVerify_IdleExpiry(t *testing.T) {
	s, _ := newStrat(t,
		session.WithAbsoluteTTL(10*time.Second),
		session.WithIdleTimeout(20*time.Millisecond),
	)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	time.Sleep(50 * time.Millisecond)
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected idle expiry, got %v", err)
	}
}

func TestVerify_IdleRollingExtends(t *testing.T) {
	s, _ := newStrat(t,
		session.WithAbsoluteTTL(10*time.Second),
		session.WithIdleTimeout(40*time.Millisecond),
	)
	creds, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	for i := 0; i < 4; i++ {
		time.Sleep(15 * time.Millisecond)
		if _, err := s.Verify(context.Background(), creds.Access); err != nil {
			t.Fatalf("Verify %d failed: %v", i, err)
		}
	}
}

func TestRevokeAllForUser(t *testing.T) {
	s, _ := newStrat(t, session.WithAbsoluteTTL(time.Minute))
	a, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	b, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	c, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u2"})
	if err := s.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), a.Access); err == nil {
		t.Error("a should be revoked")
	}
	if _, err := s.Verify(context.Background(), b.Access); err == nil {
		t.Error("b should be revoked")
	}
	if _, err := s.Verify(context.Background(), c.Access); err != nil {
		t.Errorf("c should remain: %v", err)
	}
}

func TestRevokeOldOnIssue(t *testing.T) {
	s, _ := newStrat(t,
		session.WithAbsoluteTTL(time.Minute),
		session.WithRevokeOldOnIssue(true),
	)
	a, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	b, _ := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), a.Access); err == nil {
		t.Error("first session should be revoked when WithRevokeOldOnIssue is on")
	}
	if _, err := s.Verify(context.Background(), b.Access); err != nil {
		t.Errorf("new session should verify: %v", err)
	}
}

func TestVerify_UnknownSID(t *testing.T) {
	s, _ := newStrat(t)
	if _, err := s.Verify(context.Background(), "not-a-real-sid"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestSIDsAreUnique(t *testing.T) {
	s, _ := newStrat(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		c, err := s.Issue(context.Background(), multipass.Principal{UserID: "u"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[c.Access] {
			t.Fatalf("collision after %d issues", i)
		}
		seen[c.Access] = true
	}
}

type failingSessionStore struct {
	*memory.SessionStore
	touchErr, deleteErr error
}

func (f *failingSessionStore) Touch(ctx context.Context, sid string, ttl time.Duration) error {
	if f.touchErr != nil {
		return f.touchErr
	}
	return f.SessionStore.Touch(ctx, sid, ttl)
}

func (f *failingSessionStore) Delete(ctx context.Context, sid string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.SessionStore.Delete(ctx, sid)
}

// A swallowed Touch error looked like success, then logged the user out at
// the next idle deadline with no trace of why.
func TestVerify_TouchFailureIsReturned(t *testing.T) {
	boom := errors.New("store down")
	st := &failingSessionStore{SessionStore: memory.NewSessionStore(), touchErr: boom}
	s, err := session.New(st, session.WithIdleTimeout(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, boom) {
		t.Fatalf("expected touch error, got %v", err)
	}
}

type sessClock struct{ t time.Time }

func (c *sessClock) Now() time.Time { return c.t }

// The strategy's clock runs past the absolute TTL while the store's own TTL
// (wall clock) has not elapsed, so Verify reaches its expiry branch and has
// to delete the row itself.
func TestVerify_ExpiredDeleteFailureReachesHandler(t *testing.T) {
	boom := errors.New("delete failed")
	st := &failingSessionStore{SessionStore: memory.NewSessionStore(), deleteErr: boom}
	clock := &sessClock{t: time.Now()}
	var got error
	s, err := session.New(st, session.WithAbsoluteTTL(time.Hour), session.WithClock(clock),
		session.WithErrorHandler(func(_ context.Context, err error) { got = err }))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(2 * time.Hour)
	if _, err := s.Verify(context.Background(), creds.Access); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	if !errors.Is(got, boom) {
		t.Fatalf("handler got %v, want delete error", got)
	}
}
