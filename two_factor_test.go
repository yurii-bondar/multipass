package multipass_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yurii-bondar/multipass"
)

// fakeSecondFactor is a minimal multipass.SecondFactor implementation.
type fakeSecondFactor struct {
	verifyP   *multipass.Principal
	verifyErr error
	gotRaw    string
}

func (f *fakeSecondFactor) Verify(_ context.Context, raw string) (*multipass.Principal, error) {
	f.gotRaw = raw
	return f.verifyP, f.verifyErr
}

func TestTwoFactorGate_Name_ProxiesInner(t *testing.T) {
	inner := &fakeStrategy{name: "jwt"}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	if gate.Name() != "jwt" {
		t.Fatalf("Name() = %q, want %q", gate.Name(), "jwt")
	}
}

func TestTwoFactorGate_Issue_UnconditionalWithoutRequirement_DemandsCode(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})

	_, err := gate.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if !errors.Is(err, multipass.ErrTwoFactorRequired) {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}
}

func TestTwoFactorGate_Issue_WithCode_Success(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	second := &fakeSecondFactor{verifyP: &multipass.Principal{UserID: "u1"}}
	gate := multipass.RequireTwoFactor(inner, second)

	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"2fa_code": "u1:123456"}}
	creds, err := gate.Issue(context.Background(), p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if creds.Access != "tok" || creds.Subject != "u1" {
		t.Errorf("unexpected creds: %+v", creds)
	}
	if second.gotRaw != "u1:123456" {
		t.Errorf("second factor did not receive raw code: %q", second.gotRaw)
	}
}

func TestTwoFactorGate_Issue_SecondFactorError(t *testing.T) {
	inner := &fakeStrategy{name: "jwt"}
	second := &fakeSecondFactor{verifyErr: multipass.ErrTokenInvalid}
	gate := multipass.RequireTwoFactor(inner, second)

	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"2fa_code": "bad"}}
	_, err := gate.Issue(context.Background(), p)
	if !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestTwoFactorGate_Issue_SecondFactorUserMismatch(t *testing.T) {
	inner := &fakeStrategy{name: "jwt"}
	second := &fakeSecondFactor{verifyP: &multipass.Principal{UserID: "someone-else"}}
	gate := multipass.RequireTwoFactor(inner, second)

	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"2fa_code": "code"}}
	_, err := gate.Issue(context.Background(), p)
	if !errors.Is(err, multipass.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestTwoFactorGate_WithRequirement_False_SkipsSecondFactor(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	second := &fakeSecondFactor{}
	req := multipass.TwoFactorRequirementFunc(func(_ context.Context, userID string) (bool, error) {
		return false, nil
	})
	gate := multipass.RequireTwoFactor(inner, second, multipass.WithRequirement(req))

	creds, err := gate.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if creds.Access != "tok" {
		t.Errorf("unexpected creds: %+v", creds)
	}
	if second.gotRaw != "" {
		t.Error("second factor should not have been consulted")
	}
}

func TestTwoFactorGate_WithRequirement_True_DemandsCode(t *testing.T) {
	inner := &fakeStrategy{name: "jwt"}
	req := multipass.TwoFactorRequirementFunc(func(_ context.Context, userID string) (bool, error) {
		return true, nil
	})
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{}, multipass.WithRequirement(req))

	_, err := gate.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if !errors.Is(err, multipass.ErrTwoFactorRequired) {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}
}

func TestTwoFactorGate_WithRequirement_Error(t *testing.T) {
	boom := errors.New("boom")
	inner := &fakeStrategy{name: "jwt"}
	req := multipass.TwoFactorRequirementFunc(func(_ context.Context, userID string) (bool, error) {
		return false, boom
	})
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{}, multipass.WithRequirement(req))

	_, err := gate.Issue(context.Background(), multipass.Principal{UserID: "u1"})
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped boom error, got %v", err)
	}
}

func TestTwoFactorGate_WithExtraKey(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	second := &fakeSecondFactor{verifyP: &multipass.Principal{UserID: "u1"}}
	gate := multipass.RequireTwoFactor(inner, second, multipass.WithExtraKey("webauthn_assertion"))

	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"webauthn_assertion": "envelope"}}
	if _, err := gate.Issue(context.Background(), p); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if second.gotRaw != "envelope" {
		t.Errorf("gate did not read the configured extra key: %q", second.gotRaw)
	}
}

func TestTwoFactorGate_Verify_Revoke_Passthrough(t *testing.T) {
	inner := &fakeStrategy{name: "jwt", verifyP: &multipass.Principal{UserID: "u1"}}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})

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
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	if _, err := gate.Refresh(context.Background(), "x"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_Refresh_PassthroughWhenInnerRefreshable(t *testing.T) {
	inner := refreshableStrategy{fakeStrategy: &fakeStrategy{name: "jwt"}}
	inner.refreshed = multipass.Credentials{Access: "new"}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})

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
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	if err := gate.RevokeAllForUser(context.Background(), "u1"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_RevokeAllForUser_PassthroughWhenInnerSupports(t *testing.T) {
	inner := revokeAllStrategy{fakeStrategy: &fakeStrategy{name: "session"}}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	if err := gate.RevokeAllForUser(context.Background(), "u1"); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if inner.fakeStrategy.revokedAllFor != "u1" {
		t.Errorf("RevokeAllForUser did not propagate: %q", inner.fakeStrategy.revokedAllFor)
	}
}

func TestTwoFactorGate_Authenticate_UnsupportedByInner(t *testing.T) {
	inner := &fakeStrategy{name: "local"}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	if _, err := gate.Authenticate(context.Background(), "id", "secret"); !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestTwoFactorGate_Authenticate_PassthroughWhenInnerSupports(t *testing.T) {
	inner := authStrategy{fakeStrategy: &fakeStrategy{name: "local"}}
	gate := multipass.RequireTwoFactor(inner, &fakeSecondFactor{})
	p, err := gate.Authenticate(context.Background(), "alice", "pwd")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != "u-alice" {
		t.Errorf("unexpected principal: %+v", p)
	}
}

// TestTwoFactorGate_RegisteredOnService is an end-to-end check that a gate
// slots into Service exactly like the strategy it wraps: same name, same
// Issue/Verify/Revoke call sites.
func TestTwoFactorGate_RegisteredOnService(t *testing.T) {
	svc := multipass.New(nil)
	inner := &fakeStrategy{name: "jwt", issued: multipass.Credentials{Access: "tok"}}
	second := &fakeSecondFactor{verifyP: &multipass.Principal{UserID: "u1"}}
	svc.Register(multipass.RequireTwoFactor(inner, second))

	// Without a code: blocked.
	_, err := svc.Issue(context.Background(), "jwt", multipass.Principal{UserID: "u1"})
	if !errors.Is(err, multipass.ErrTwoFactorRequired) {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}

	// With a code: succeeds through the normal Service.Issue call site.
	p := multipass.Principal{UserID: "u1", Extra: map[string]any{"2fa_code": "123456"}}
	creds, err := svc.Issue(context.Background(), "jwt", p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if creds.Access != "tok" {
		t.Errorf("unexpected creds: %+v", creds)
	}
}
