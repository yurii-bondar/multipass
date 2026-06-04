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
	s, err := magiclink.NewNumericOTP(st, send, 6)
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
