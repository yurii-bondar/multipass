package multipass_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
)

// fakeSecondFactor accepts exactly one input and records the userID it was
// asked to verify.
type fakeSecondFactor struct {
	valid     string
	err       error
	gotUserID string
	calls     int
}

func (f *fakeSecondFactor) VerifySecondFactor(_ context.Context, userID, input string) error {
	f.calls++
	f.gotUserID = userID
	if f.err != nil {
		return f.err
	}
	if input != f.valid {
		return multipass.ErrTokenInvalid
	}
	return nil
}

type stepClock struct{ t time.Time }

func (c *stepClock) Now() time.Time { return c.t }

func newGate(t *testing.T, inner multipass.Strategy, second multipass.SecondFactor, opts ...multipass.TwoFactorOption) *multipass.TwoFactorGate {
	t.Helper()
	g, err := multipass.RequireTwoFactor(inner, second, memory.NewOTPStore(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// pendingToken runs the first step of a gated login and returns the token
// the client would carry to the second step.
func pendingToken(t *testing.T, g *multipass.TwoFactorGate, p multipass.Principal) string {
	t.Helper()
	_, err := g.Issue(context.Background(), p)
	var pending *multipass.TwoFactorPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("expected *TwoFactorPendingError, got %v", err)
	}
	if !errors.Is(err, multipass.ErrTwoFactorRequired) {
		t.Fatal("pending error must match ErrTwoFactorRequired")
	}
	if pending.Token == "" {
		t.Fatal("empty pending token")
	}
	return pending.Token
}

func TestTwoFactorGate_Name_ProxiesInner(t *testing.T) {
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{})
	if gate.Name() != "jwt" {
		t.Fatalf("Name() = %q, want %q", gate.Name(), "jwt")
	}
}

func TestRequireTwoFactor_RequiresDependencies(t *testing.T) {
	tests := []struct {
		name    string
		inner   multipass.Strategy
		second  multipass.SecondFactor
		pending *memory.OTPStore
		opts    []multipass.TwoFactorOption
	}{
		{"nil inner", nil, &fakeSecondFactor{}, memory.NewOTPStore(), nil},
		{"nil second factor", &fakeStrategy{name: "jwt"}, nil, memory.NewOTPStore(), nil},
		{"nil pending store", &fakeStrategy{name: "jwt"}, &fakeSecondFactor{}, nil, nil},
		{"zero attempts", &fakeStrategy{name: "jwt"}, &fakeSecondFactor{}, memory.NewOTPStore(), []multipass.TwoFactorOption{multipass.WithMaxAttempts(0)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.pending == nil {
				_, err = multipass.RequireTwoFactor(tc.inner, tc.second, nil, tc.opts...)
			} else {
				_, err = multipass.RequireTwoFactor(tc.inner, tc.second, tc.pending, tc.opts...)
			}
			if err == nil {
				t.Fatal("expected constructor error")
			}
		})
	}
}

func TestTwoFactorGate_IssueThenComplete(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	second := &fakeSecondFactor{valid: "123456"}
	gate := newGate(t, inner, second)

	token := pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	creds, err := gate.CompleteTwoFactor(context.Background(), token, "123456")
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	if creds.Access != "tok" || creds.Subject != "u1" {
		t.Errorf("unexpected creds: %+v", creds)
	}
	if second.gotUserID != "u1" {
		t.Errorf("second factor checked for %q, want the pending principal u1", second.gotUserID)
	}
}

// The old gate minted a credential for any Principal that carried a valid
// code, so an app that kept the userID client-side between the password and
// the code step let an attacker skip the password. The second step must only
// be reachable through a pending login created after the primary factor.
func TestTwoFactorGate_CompleteWithoutPendingLogin(t *testing.T) {
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{valid: "123456"})
	for _, token := range []string{"", "forged-token", "u1"} {
		if _, err := gate.CompleteTwoFactor(context.Background(), token, "123456"); !errors.Is(err, multipass.ErrTokenInvalid) {
			t.Errorf("token %q: expected ErrTokenInvalid, got %v", token, err)
		}
	}
}

// A code smuggled in Principal.Extra must not bypass the challenge — and must
// never end up persisted by the inner strategy (sessions store Extra).
func TestTwoFactorGate_IgnoresCodeInExtra(t *testing.T) {
	second := &fakeSecondFactor{valid: "123456"}
	gate := newGate(t, &fakeStrategy{name: "jwt"}, second)
	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"2fa_code": "u1:123456"}}
	pendingToken(t, gate, p)
	if second.calls != 0 {
		t.Fatal("Issue must not verify a second factor itself")
	}
}

func TestTwoFactorGate_PendingTokenIsSingleUse(t *testing.T) {
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{valid: "123456"})
	token := pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	if _, err := gate.CompleteTwoFactor(context.Background(), token, "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.CompleteTwoFactor(context.Background(), token, "123456"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("reused token: expected ErrTokenInvalid, got %v", err)
	}
}

func TestTwoFactorGate_WrongCodeAttempts(t *testing.T) {
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{valid: "123456"}, multipass.WithMaxAttempts(2))
	ctx := context.Background()

	token := pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	if _, err := gate.CompleteTwoFactor(ctx, token, "000000"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	// A typo does not force the user back to the password step.
	if _, err := gate.CompleteTwoFactor(ctx, token, "123456"); err != nil {
		t.Fatalf("retry with correct code: %v", err)
	}

	// Exhausting the budget discards the pending login entirely.
	token = pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	for i := 0; i < 2; i++ {
		if _, err := gate.CompleteTwoFactor(ctx, token, "000000"); !errors.Is(err, multipass.ErrTokenInvalid) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := gate.CompleteTwoFactor(ctx, token, "123456"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("after max attempts the token must be gone, got %v", err)
	}
}

func TestTwoFactorGate_PendingExpires(t *testing.T) {
	clock := &stepClock{t: time.Unix(1_700_000_000, 0)}
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{valid: "123456"},
		multipass.WithPendingTTL(time.Minute), multipass.WithTwoFactorClock(clock))
	token := pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	clock.t = clock.t.Add(2 * time.Minute)
	if _, err := gate.CompleteTwoFactor(context.Background(), token, "123456"); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestTwoFactorGate_SecondFactorError(t *testing.T) {
	boom := errors.New("boom")
	gate := newGate(t, &fakeStrategy{name: "jwt"}, &fakeSecondFactor{err: boom})
	token := pendingToken(t, gate, multipass.Principal{UserID: "u1"})
	if _, err := gate.CompleteTwoFactor(context.Background(), token, "x"); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
}

func TestTwoFactorGate_WithRequirement(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name       string
		required   bool
		reqErr     error
		wantAccess string
		wantErr    error
	}{
		{"not enrolled issues directly", false, nil, "tok", nil},
		{"enrolled gets a challenge", true, nil, "", multipass.ErrTwoFactorRequired},
		{"requirement lookup error", false, boom, "", boom},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			second := &fakeSecondFactor{}
			req := multipass.TwoFactorRequirementFunc(func(_ context.Context, _ string) (bool, error) {
				return tc.required, tc.reqErr
			})
			gate := newGate(t, &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}, second, multipass.WithRequirement(req))
			creds, err := gate.Issue(context.Background(), multipass.Principal{UserID: "u1"})
			if tc.wantErr == nil && err != nil {
				t.Fatalf("Issue: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if creds.Access != tc.wantAccess {
				t.Errorf("Access = %q, want %q", creds.Access, tc.wantAccess)
			}
			if second.calls != 0 {
				t.Error("Issue must not consult the second factor")
			}
		})
	}
}

func TestTwoFactorGate_Verify_Revoke_Passthrough(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", verifyP: &multipass.Principal{UserID: "u1"}}
	gate := newGate(t, inner, &fakeSecondFactor{})

	p, err := gate.Verify(context.Background(), "raw-token")
	if err != nil || p.UserID != "u1" {
		t.Fatalf("Verify: %+v, %v", p, err)
	}
	if err := gate.Revoke(context.Background(), "raw-token"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if inner.revoked != "raw-token" {
		t.Errorf("Revoke did not propagate: %q", inner.revoked)
	}
}

func TestTwoFactorGate_Refresh_UnsupportedByInner(t *testing.T) {
	inner := &fakeStrategy{name: "session"} // base only, not Refreshable
	gate := newGate(t, inner, &fakeSecondFactor{})
	if _, err := gate.Refresh(context.Background(), "x"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_Refresh_PassthroughWhenInnerRefreshable(t *testing.T) {
	inner := refreshableStrategy{fakeStrategy: &fakeStrategy{name: "jwt"}}
	inner.refreshed = multipass.Credentials{Access: "new"}
	gate := newGate(t, inner, &fakeSecondFactor{})

	creds, err := gate.Refresh(context.Background(), "old")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if creds.Access != "new" {
		t.Errorf("creds.Access = %q", creds.Access)
	}
}

func TestTwoFactorGate_RevokeAllForUser_UnsupportedByInner(t *testing.T) {
	inner := &fakeStrategy{name: "apikey"}
	gate := newGate(t, inner, &fakeSecondFactor{})
	if err := gate.RevokeAllForUser(context.Background(), "u1"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_RevokeAllForUser_PassthroughWhenInnerSupports(t *testing.T) {
	inner := revokeAllStrategy{fakeStrategy: &fakeStrategy{name: "session"}}
	gate := newGate(t, inner, &fakeSecondFactor{})
	if err := gate.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if inner.fakeStrategy.revokedAllFor != "u1" {
		t.Errorf("RevokeAllForUser did not propagate: %q", inner.fakeStrategy.revokedAllFor)
	}
}

func TestTwoFactorGate_Authenticate_UnsupportedByInner(t *testing.T) {
	inner := &fakeStrategy{name: "local"}
	gate := newGate(t, inner, &fakeSecondFactor{})
	if _, err := gate.Authenticate(context.Background(), "id", "secret"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_Authenticate_PassthroughWhenInnerSupports(t *testing.T) {
	inner := authStrategy{fakeStrategy: &fakeStrategy{name: "local"}}
	gate := newGate(t, inner, &fakeSecondFactor{})
	p, err := gate.Authenticate(context.Background(), "alice", "pwd")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != "u-alice" {
		t.Errorf("unexpected principal: %+v", p)
	}
}

// TestTwoFactorGate_RegisteredOnService is an end-to-end check that a gate
// slots into Service exactly like the strategy it wraps, and that
// Service.CompleteTwoFactor finishes the login.
func TestTwoFactorGate_RegisteredOnService(t *testing.T) {
	svc := multipass.New(nil)
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	svc.Register(newGate(t, inner, &fakeSecondFactor{valid: "123456"}))
	svc.Register(&fakeStrategy{name: "plain"})
	ctx := context.Background()

	_, err := svc.Issue(ctx, "jwt", multipass.Principal{UserID: "u1"})
	var pending *multipass.TwoFactorPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("expected pending error, got %v", err)
	}
	creds, err := svc.CompleteTwoFactor(ctx, "jwt", pending.Token, "123456")
	if err != nil {
		t.Fatalf("CompleteTwoFactor: %v", err)
	}
	if creds.Access != "tok" {
		t.Errorf("unexpected creds: %+v", creds)
	}
	if _, err := svc.CompleteTwoFactor(ctx, "plain", "t", "c"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation for an ungated strategy, got %v", err)
	}
}
