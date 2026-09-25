package magiclink_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
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
	s, err := magiclink.NewTOTP(store, memory.NewTOTPGuard(), magiclink.TOTPWithIssuer("AppX"))
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
	s, _ := magiclink.NewTOTP(secretStore{}, memory.NewTOTPGuard())
	if _, err := s.Verify(context.Background(), "ghost:123456"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
}

func TestTOTP_MalformedRaw(t *testing.T) {
	s, _ := magiclink.NewTOTP(secretStore{}, memory.NewTOTPGuard())
	for _, raw := range []string{"", ":", "no-colon", ":code", "user:"} {
		if _, err := s.Verify(context.Background(), raw); !errors.Is(err, multipass.ErrTokenInvalid) {
			t.Errorf("raw %q expected ErrTokenInvalid, got %v", raw, err)
		}
	}
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

// newEnrolledTOTP returns a strategy with user "u1" enrolled and a clock the
// test controls, so code generation and verification see the same instant.
func newEnrolledTOTP(t *testing.T, opts ...magiclink.TOTPOption) (*magiclink.TOTPStrategy, string, *fixedClock) {
	t.Helper()
	clock := &fixedClock{t: time.Unix(1_700_000_000, 0)}
	secrets := secretStore{}
	opts = append([]magiclink.TOTPOption{magiclink.TOTPWithClock(clock)}, opts...)
	s, err := magiclink.NewTOTP(secrets, memory.NewTOTPGuard(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.Issue(context.Background(), multipass.Principal{UserID: "u1", Email: "u@x.io"})
	if err != nil {
		t.Fatal(err)
	}
	secrets["u1"] = creds.Refresh
	return s, creds.Refresh, clock
}

// RFC 6238 §5.2: a verifier MUST NOT accept the second attempt of the same
// OTP after a successful validation — otherwise a code observed over the
// shoulder or in a phished session stays usable for the whole skew window.
func TestTOTP_RejectsReplayedCode(t *testing.T) {
	s, secret, clock := newEnrolledTOTP(t)
	ctx := context.Background()
	code, err := magiclink.GenerateCode(secret, clock.t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(ctx, "u1:"+code); err != nil {
		t.Fatalf("first use: %v", err)
	}
	clock.t = clock.t.Add(20 * time.Second) // still inside the skew window
	if _, err := s.Verify(ctx, "u1:"+code); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("replayed code: expected ErrTokenInvalid, got %v", err)
	}
}

// A code from an earlier period than one already accepted is also a replay,
// even if it was never used itself.
func TestTOTP_RejectsOlderCodeAfterNewerAccepted(t *testing.T) {
	s, secret, clock := newEnrolledTOTP(t)
	ctx := context.Background()
	older, _ := magiclink.GenerateCode(secret, clock.t.Add(-30*time.Second))
	current, _ := magiclink.GenerateCode(secret, clock.t)
	if older == current {
		t.Skip("adjacent periods produced the same code")
	}
	if _, err := s.Verify(ctx, "u1:"+current); err != nil {
		t.Fatalf("current code: %v", err)
	}
	if _, err := s.Verify(ctx, "u1:"+older); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("older code: expected ErrTokenInvalid, got %v", err)
	}
}

func TestTOTP_AcceptsNextPeriodCode(t *testing.T) {
	s, secret, clock := newEnrolledTOTP(t)
	ctx := context.Background()
	first, _ := magiclink.GenerateCode(secret, clock.t)
	if _, err := s.Verify(ctx, "u1:"+first); err != nil {
		t.Fatal(err)
	}
	clock.t = clock.t.Add(30 * time.Second)
	next, _ := magiclink.GenerateCode(secret, clock.t)
	if _, err := s.Verify(ctx, "u1:"+next); err != nil {
		t.Fatalf("code of the next period must be accepted: %v", err)
	}
}

// Without a cap, 3 valid codes out of 10^6 fall to a scripted brute force in
// hours. After maxAttempts even the correct code is refused until the window
// elapses, so guessing gains nothing.
func TestTOTP_AttemptLimit(t *testing.T) {
	s, secret, clock := newEnrolledTOTP(t, magiclink.TOTPWithMaxAttempts(3, time.Hour))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.Verify(ctx, "u1:000000"); errors.Is(err, multipass.ErrRateLimited) {
			t.Fatalf("attempt %d rate limited too early", i+1)
		}
	}
	good, _ := magiclink.GenerateCode(secret, clock.t)
	if _, err := s.Verify(ctx, "u1:"+good); !errors.Is(err, multipass.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited after budget exhausted, got %v", err)
	}
}

func TestTOTP_SuccessResetsAttempts(t *testing.T) {
	s, secret, clock := newEnrolledTOTP(t, magiclink.TOTPWithMaxAttempts(2, time.Hour))
	ctx := context.Background()
	if _, err := s.Verify(ctx, "u1:000000"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	good, _ := magiclink.GenerateCode(secret, clock.t)
	if _, err := s.Verify(ctx, "u1:"+good); err != nil {
		t.Fatalf("good code: %v", err)
	}
	// Budget is back to 2: one wrong attempt must not be rate limited.
	if _, err := s.Verify(ctx, "u1:000000"); errors.Is(err, multipass.ErrRateLimited) {
		t.Fatal("successful verification must reset the attempt counter")
	}
}

func TestNewTOTP_RequiresDependencies(t *testing.T) {
	tests := []struct {
		name    string
		secrets magiclink.TOTPSecretStore
		guard   *memory.TOTPGuard
		opts    []magiclink.TOTPOption
	}{
		{"nil secret store", nil, memory.NewTOTPGuard(), nil},
		{"nil guard", secretStore{}, nil, nil},
		{"zero attempts", secretStore{}, memory.NewTOTPGuard(), []magiclink.TOTPOption{magiclink.TOTPWithMaxAttempts(0, time.Minute)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.guard == nil {
				_, err = magiclink.NewTOTP(tc.secrets, nil, tc.opts...)
			} else {
				_, err = magiclink.NewTOTP(tc.secrets, tc.guard, tc.opts...)
			}
			if err == nil {
				t.Fatal("expected constructor error")
			}
		})
	}
}
