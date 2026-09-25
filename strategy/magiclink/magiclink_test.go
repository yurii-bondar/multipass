package magiclink_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/magiclink"
)

// captureSender records the last sent payload, so the test can pretend to
// "open the email" by inspecting it.
type captureSender struct {
	mu       sync.Mutex
	to, body string
	count    int
	fail     error
}

func (c *captureSender) Send(_ context.Context, to, payload string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if c.fail != nil {
		return c.fail
	}
	c.to, c.body = to, payload
	return nil
}

func TestRequestVerify_RoundTrip(t *testing.T) {
	st := memory.NewOTPStore()
	send := &captureSender{}
	s, err := magiclink.New(st, send,
		magiclink.WithTTL(time.Minute),
		magiclink.WithURLPrefix("https://app.test/auth?token="),
	)
	if err != nil {
		t.Fatal(err)
	}
	code, err := s.Request(context.Background(), "u@x.io", multipass.Principal{UserID: "u1", Email: "u@x.io"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(send.body, "https://app.test/auth?token=") {
		t.Errorf("sender did not receive URL, got %q", send.body)
	}
	if !strings.HasSuffix(send.body, code) {
		t.Errorf("sender body should contain code")
	}
	p, err := s.Verify(context.Background(), send.body) // verify via full URL
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "u1" || p.Email != "u@x.io" {
		t.Errorf("principal: %+v", p)
	}
}

func TestVerify_SingleUse(t *testing.T) {
	st := memory.NewOTPStore()
	s, _ := magiclink.New(st, &captureSender{})
	code, _ := s.Request(context.Background(), "u@x.io", multipass.Principal{UserID: "u1"})
	if _, err := s.Verify(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), code); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected single-use rejection, got %v", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	st := memory.NewOTPStore()
	s, _ := magiclink.New(st, &captureSender{}, magiclink.WithTTL(15*time.Millisecond))
	code, _ := s.Request(context.Background(), "u@x.io", multipass.Principal{UserID: "u1"})
	time.Sleep(40 * time.Millisecond)
	if _, err := s.Verify(context.Background(), code); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestPurpose_Mismatch(t *testing.T) {
	st := memory.NewOTPStore()
	login, _ := magiclink.New(st, &captureSender{}, magiclink.WithPurpose("login"))
	reset, _ := magiclink.New(st, &captureSender{}, magiclink.WithPurpose("password-reset"))
	code, _ := login.Request(context.Background(), "u@x.io", multipass.Principal{UserID: "u1"})
	if _, err := reset.Verify(context.Background(), code); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected purpose mismatch, got %v", err)
	}
}

func TestNumericOTP(t *testing.T) {
	st := memory.NewOTPStore()
	send := &captureSender{}
	s, err := magiclink.NewNumericOTP(st, send, 6, &countingLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	code, _ := s.Request(context.Background(), "+15555555555", multipass.Principal{UserID: "u1"})
	if len(code) != 6 {
		t.Errorf("expected 6 digits, got %d", len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("non-digit in code: %q", code)
			break
		}
	}
}

type alwaysReject struct{}

func (alwaysReject) Allow(_ context.Context, _ string) error { return multipass.ErrRateLimited }

func TestRateLimiter(t *testing.T) {
	st := memory.NewOTPStore()
	s, _ := magiclink.New(st, &captureSender{}, magiclink.WithRateLimiter(alwaysReject{}))
	if _, err := s.Request(context.Background(), "u@x.io", multipass.Principal{UserID: "u1"}); !errors.Is(err, multipass.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
}

// countingLimiter allows up to max calls per key (0 = unlimited) and records
// the keys it was asked about.
type countingLimiter struct {
	mu   sync.Mutex
	max  int
	seen map[string]int
}

func (l *countingLimiter) Allow(_ context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]int{}
	}
	l.seen[key]++
	if l.max > 0 && l.seen[key] > l.max {
		return multipass.ErrRateLimited
	}
	return nil
}

func newNumeric(t *testing.T, lim *countingLimiter) *magiclink.Strategy {
	t.Helper()
	s, err := magiclink.NewNumericOTP(memory.NewOTPStore(), &captureSender{}, 6, lim)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNumericOTP_RoundTrip(t *testing.T) {
	s := newNumeric(t, &countingLimiter{})
	ctx := context.Background()
	code, err := s.Request(ctx, "A@X.io", multipass.Principal{UserID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	// Recipient matching is case- and whitespace-insensitive.
	p, err := s.Verify(ctx, " a@x.io:"+code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != "a" {
		t.Fatalf("principal: %+v", p)
	}
}

// A 6-digit code is unique only per recipient. If codes were keyed by value
// alone, a code issued to A could be redeemed by anyone, and two users drawing
// the same code would overwrite each other so A logs in as B.
func TestNumericOTP_BoundToRecipient(t *testing.T) {
	s := newNumeric(t, &countingLimiter{})
	ctx := context.Background()
	codeA, _ := s.Request(ctx, "a@x.io", multipass.Principal{UserID: "a"})
	codeB, _ := s.Request(ctx, "b@x.io", multipass.Principal{UserID: "b"})
	if codeA == codeB {
		t.Skip("both recipients drew the same code; cross-redeem check is meaningless")
	}

	if _, err := s.Verify(ctx, "b@x.io:"+codeA); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("A's code redeemed for B: %v", err)
	}
	pa, err := s.Verify(ctx, "a@x.io:"+codeA)
	if err != nil || pa.UserID != "a" {
		t.Fatalf("A's own code: %+v, %v", pa, err)
	}
	pb, err := s.Verify(ctx, "b@x.io:"+codeB)
	if err != nil || pb.UserID != "b" {
		t.Fatalf("B's own code: %+v, %v", pb, err)
	}
}

func TestNumericOTP_VerifyRateLimited(t *testing.T) {
	lim := &countingLimiter{max: 2}
	s := newNumeric(t, lim)
	ctx := context.Background()
	code, _ := s.Request(ctx, "a@x.io", multipass.Principal{UserID: "a"})
	for i := 0; i < 2; i++ {
		if _, err := s.Verify(ctx, "a@x.io:000000"); errors.Is(err, multipass.ErrRateLimited) {
			t.Fatalf("attempt %d rate limited too early", i+1)
		}
	}
	if _, err := s.Verify(ctx, "a@x.io:"+code); !errors.Is(err, multipass.ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited once budget is spent, got %v", err)
	}
	if lim.seen["verify:a@x.io"] != 3 {
		t.Fatalf("limiter keys: %v", lim.seen)
	}
}

func TestNumericOTP_MalformedRaw(t *testing.T) {
	s := newNumeric(t, &countingLimiter{})
	for _, raw := range []string{"", "123456", ":123456", "a@x.io:"} {
		if _, err := s.Verify(context.Background(), raw); !errors.Is(err, multipass.ErrTokenInvalid) {
			t.Errorf("raw %q: expected ErrTokenInvalid, got %v", raw, err)
		}
	}
}

func TestNewNumericOTP_RequiresVerifyLimiter(t *testing.T) {
	if _, err := magiclink.NewNumericOTP(memory.NewOTPStore(), &captureSender{}, 6, nil); err == nil {
		t.Fatal("expected error without a verify RateLimiter")
	}
}
