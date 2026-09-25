package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass/store"
)

func TestSessionStore_RoundTrip(t *testing.T) {
	s := NewSessionStore()
	ctx := context.Background()
	if err := s.Save(ctx, "sid1", store.SessionData{UserID: "u1"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	d, err := s.Get(ctx, "sid1")
	if err != nil || d.UserID != "u1" {
		t.Fatalf("Get: %v / %+v", err, d)
	}
	_ = s.Delete(ctx, "sid1")
	if _, err := s.Get(ctx, "sid1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSessionStore_Expiry(t *testing.T) {
	s := NewSessionStore()
	_ = s.Save(context.Background(), "x", store.SessionData{UserID: "u"}, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Get(context.Background(), "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected expiry to remove key, got %v", err)
	}
}

func TestSessionStore_DeleteByUser(t *testing.T) {
	s := NewSessionStore()
	_ = s.Save(context.Background(), "a", store.SessionData{UserID: "u1"}, time.Minute)
	_ = s.Save(context.Background(), "b", store.SessionData{UserID: "u1"}, time.Minute)
	_ = s.Save(context.Background(), "c", store.SessionData{UserID: "u2"}, time.Minute)
	_ = s.DeleteByUser(context.Background(), "u1")
	if _, err := s.Get(context.Background(), "a"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a should be gone")
	}
	if _, err := s.Get(context.Background(), "c"); err != nil {
		t.Errorf("c should remain: %v", err)
	}
}

func TestBlacklist(t *testing.T) {
	b := NewBlacklist()
	ctx := context.Background()
	_ = b.Add(ctx, "j1", time.Now().Add(time.Minute))
	if has, _ := b.Has(ctx, "j1"); !has {
		t.Fatal("j1 should be blacklisted")
	}
	if has, _ := b.Has(ctx, "missing"); has {
		t.Fatal("missing should not be blacklisted")
	}
}

func TestBlacklist_AutoExpiry(t *testing.T) {
	b := NewBlacklist()
	_ = b.Add(context.Background(), "j", time.Now().Add(-time.Second))
	if has, _ := b.Has(context.Background(), "j"); has {
		t.Fatal("expired entry should not match")
	}
}

func TestRefreshStore_RotateHappyPath(t *testing.T) {
	r := NewRefreshStore()
	ctx := context.Background()
	_ = r.Save(ctx, store.RefreshRecord{
		JTI: "old", UserID: "u", FamilyID: "f", ExpiresAt: time.Now().Add(time.Hour),
	})
	_, reused, err := r.RotateAndCheck(ctx, "old", "new", time.Now().Add(time.Hour))
	if err != nil || reused {
		t.Fatalf("rotate: err=%v reused=%v", err, reused)
	}
}

func TestRefreshStore_ReuseDetected(t *testing.T) {
	r := NewRefreshStore()
	ctx := context.Background()
	_ = r.Save(ctx, store.RefreshRecord{
		JTI: "old", UserID: "u", FamilyID: "f", ExpiresAt: time.Now().Add(time.Hour),
	})
	_, _, _ = r.RotateAndCheck(ctx, "old", "new1", time.Now().Add(time.Hour))
	_, reused, err := r.RotateAndCheck(ctx, "old", "new2", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reused {
		t.Fatal("expected reuse=true on second rotate of old jti")
	}
}

func TestRefreshStore_KillFamily(t *testing.T) {
	r := NewRefreshStore()
	ctx := context.Background()
	_ = r.Save(ctx, store.RefreshRecord{JTI: "a", FamilyID: "f1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = r.Save(ctx, store.RefreshRecord{JTI: "b", FamilyID: "f1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = r.Save(ctx, store.RefreshRecord{JTI: "c", FamilyID: "f2", ExpiresAt: time.Now().Add(time.Hour)})
	_ = r.KillFamily(ctx, "f1")
	_, reused, err := r.RotateAndCheck(ctx, "a", "x", time.Now().Add(time.Hour))
	if !errors.Is(err, store.ErrNotFound) || reused {
		t.Errorf("a should be gone: err=%v reused=%v", err, reused)
	}
	_, _, err = r.RotateAndCheck(ctx, "c", "y", time.Now().Add(time.Hour))
	if err != nil {
		t.Errorf("c should still rotate: %v", err)
	}
}

func TestCredentialStore_SaveGetListDelete(t *testing.T) {
	c := NewCredentialStore()
	ctx := context.Background()
	id1 := []byte("cred-1")
	id2 := []byte("cred-2")

	if err := c.Save(ctx, store.WebAuthnCredential{ID: id1, UserID: "u1", Name: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(ctx, store.WebAuthnCredential{ID: id2, UserID: "u1", Name: "key"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(ctx, store.WebAuthnCredential{ID: []byte("cred-3"), UserID: "u2"}); err != nil {
		t.Fatal(err)
	}

	got, err := c.Get(ctx, id1)
	if err != nil || got.Name != "phone" {
		t.Fatalf("Get: %v / %+v", err, got)
	}

	list, err := c.ListByUser(ctx, "u1")
	if err != nil || len(list) != 2 {
		t.Fatalf("ListByUser: %v / %+v", err, list)
	}

	if err := c.Delete(ctx, id1); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, id1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	// Deleting an already-missing id is a no-op, not an error.
	if err := c.Delete(ctx, id1); err != nil {
		t.Fatalf("Delete should be idempotent: %v", err)
	}
}

func TestCredentialStore_Update(t *testing.T) {
	c := NewCredentialStore()
	ctx := context.Background()
	id := []byte("cred-1")

	if err := c.Update(ctx, store.WebAuthnCredential{ID: id, UserID: "u1"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update of unknown credential should be ErrNotFound, got %v", err)
	}

	_ = c.Save(ctx, store.WebAuthnCredential{ID: id, UserID: "u1", Name: "old"})
	if err := c.Update(ctx, store.WebAuthnCredential{ID: id, UserID: "u1", Name: "new"}); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, id)
	if err != nil || got.Name != "new" {
		t.Fatalf("Get after Update: %v / %+v", err, got)
	}
}

func TestCredentialStore_DeleteByUser(t *testing.T) {
	c := NewCredentialStore()
	ctx := context.Background()
	_ = c.Save(ctx, store.WebAuthnCredential{ID: []byte("a"), UserID: "u1"})
	_ = c.Save(ctx, store.WebAuthnCredential{ID: []byte("b"), UserID: "u1"})
	_ = c.Save(ctx, store.WebAuthnCredential{ID: []byte("c"), UserID: "u2"})

	if err := c.DeleteByUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if list, _ := c.ListByUser(ctx, "u1"); len(list) != 0 {
		t.Errorf("u1 should have no credentials left: %+v", list)
	}
	if list, _ := c.ListByUser(ctx, "u2"); len(list) != 1 {
		t.Errorf("u2 should be untouched: %+v", list)
	}
}

func TestOTPStore_SingleUse(t *testing.T) {
	o := NewOTPStore()
	ctx := context.Background()
	_ = o.Save(ctx, "code", store.OTPPayload{UserID: "u"}, time.Minute)
	p, err := o.Consume(ctx, "code")
	if err != nil || p.UserID != "u" {
		t.Fatalf("first consume: %v / %+v", err, p)
	}
	if _, err := o.Consume(ctx, "code"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second consume should be ErrNotFound, got %v", err)
	}
}

func TestTOTPGuard_AdvanceStep(t *testing.T) {
	g := NewTOTPGuard()
	ctx := context.Background()
	tests := []struct {
		name string
		step int64
		want bool
	}{
		{"first use", 100, true},
		{"same step is a replay", 100, false},
		{"older step is a replay", 99, false},
		{"newer step", 101, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := g.AdvanceStep(ctx, "u1", tc.step)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("AdvanceStep(%d) = %v, want %v", tc.step, got, tc.want)
			}
		})
	}
	// Steps are tracked per user: another user's first code is never a replay.
	if ok, _ := g.AdvanceStep(ctx, "u2", 100); !ok {
		t.Fatal("step of another user must be accepted")
	}
}

func TestTOTPGuard_AttemptWindow(t *testing.T) {
	g := NewTOTPGuard()
	ctx := context.Background()
	for want := 1; want <= 3; want++ {
		n, err := g.Attempt(ctx, "u1", time.Hour)
		if err != nil || n != want {
			t.Fatalf("Attempt #%d = %d, %v", want, n, err)
		}
	}
	if err := g.ResetAttempts(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := g.Attempt(ctx, "u1", time.Hour); n != 1 {
		t.Fatalf("after reset Attempt = %d, want 1", n)
	}
	// An elapsed window starts counting from scratch.
	if n, _ := g.Attempt(ctx, "u1", 0); n != 1 {
		t.Fatalf("after elapsed window Attempt = %d, want 1", n)
	}
}
