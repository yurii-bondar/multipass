package local_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/password"
	"github.com/yurii-bondar/multipass/strategy/local"
)

// ----- in-memory user repo -------------------------------------------------

type memUsers struct {
	mu     sync.Mutex
	byID   map[string]*multipass.User
	byMail map[string]string
}

func newMemUsers() *memUsers {
	return &memUsers{byID: map[string]*multipass.User{}, byMail: map[string]string{}}
}

func (m *memUsers) GetByID(_ context.Context, id string) (*multipass.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, multipass.ErrUserNotFound
}
func (m *memUsers) GetByEmail(_ context.Context, email string) (*multipass.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byMail[email]
	if !ok {
		return nil, multipass.ErrUserNotFound
	}
	c := *m.byID[id]
	return &c, nil
}
func (m *memUsers) Create(_ context.Context, u *multipass.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *u
	m.byID[u.ID] = &cp
	m.byMail[u.Email] = u.ID
	return nil
}
func (m *memUsers) UpdatePasswordHash(_ context.Context, id, hash string, version int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.PasswordHash = hash
		u.PasswordVer = version
	}
	return nil
}
func (m *memUsers) IncrementFailedLogin(_ context.Context, id string, lockUntil time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return 0, multipass.ErrUserNotFound
	}
	u.FailedLogins++
	if !lockUntil.IsZero() {
		u.LockedUntil = lockUntil
	}
	return u.FailedLogins, nil
}
func (m *memUsers) ResetFailedLogin(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byID[id]; ok {
		u.FailedLogins = 0
		u.LockedUntil = time.Time{}
	}
	return nil
}

// ----- helpers -------------------------------------------------------------

func fastHasher() *password.Hasher {
	return password.NewHasher(password.WithArgon2Params(password.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}))
}

func seedUser(t *testing.T, repo *memUsers, h *password.Hasher, email, pwd string) *multipass.User {
	t.Helper()
	hash, err := h.Hash(pwd)
	if err != nil {
		t.Fatal(err)
	}
	u := &multipass.User{ID: "u-" + email, Email: email, PasswordHash: hash, Roles: []string{"member"}}
	if err := repo.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// ----- tests ---------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	seedUser(t, repo, h, "alice@example.com", "Password123!")
	p, err := s.Authenticate(context.Background(), "Alice@example.com  ", "Password123!")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.UserID != "u-alice@example.com" || p.Email != "alice@example.com" {
		t.Errorf("unexpected principal: %+v", p)
	}
	if p.StrategyName != local.Name {
		t.Errorf("StrategyName not set")
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	seedUser(t, repo, h, "bob@example.com", "right")
	_, err := s.Authenticate(context.Background(), "bob@example.com", "wrong")
	if !errors.Is(err, multipass.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_UnknownUser_SameError(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	_, err := s.Authenticate(context.Background(), "ghost@example.com", "x")
	if !errors.Is(err, multipass.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

func TestAuthenticate_LockoutAfterThreshold(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h, local.WithMaxFailedLogins(3), local.WithLockoutDuration(time.Hour))
	seedUser(t, repo, h, "carl@example.com", "ok")
	for i := 0; i < 3; i++ {
		_, _ = s.Authenticate(context.Background(), "carl@example.com", "bad")
	}
	// Even with the right password, the account is now locked.
	_, err := s.Authenticate(context.Background(), "carl@example.com", "ok")
	if !errors.Is(err, multipass.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}
}

func TestAuthenticate_DisabledUser(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	u := seedUser(t, repo, h, "dora@example.com", "ok")
	u.Disabled = true
	_ = repo.Create(context.Background(), u) // overwrite with Disabled=true
	_, err := s.Authenticate(context.Background(), "dora@example.com", "ok")
	if !errors.Is(err, multipass.ErrInvalidCredentials) {
		t.Fatalf("disabled user should fail with ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_EmptyInputs(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	for _, c := range []struct{ id, pwd string }{
		{"", "x"},
		{"x", ""},
		{"   ", ""},
	} {
		if _, err := s.Authenticate(context.Background(), c.id, c.pwd); !errors.Is(err, multipass.ErrInvalidCredentials) {
			t.Errorf("%q/%q: expected ErrInvalidCredentials, got %v", c.id, c.pwd, err)
		}
	}
}

func TestAuthenticate_ResetsFailedCounterOnSuccess(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h, local.WithMaxFailedLogins(5))
	u := seedUser(t, repo, h, "ed@example.com", "right")
	for i := 0; i < 3; i++ {
		_, _ = s.Authenticate(context.Background(), "ed@example.com", "bad")
	}
	if _, err := s.Authenticate(context.Background(), "ed@example.com", "right"); err != nil {
		t.Fatalf("good login failed: %v", err)
	}
	got, _ := repo.GetByID(context.Background(), u.ID)
	if got.FailedLogins != 0 {
		t.Errorf("FailedLogins not reset: %d", got.FailedLogins)
	}
}

// Token strategies embed Principal.PasswordVer; if local dropped it, every
// token would carry version 0 and a password change could not revoke them.
func TestAuthenticate_CarriesPasswordVersion(t *testing.T) {
	repo := newMemUsers()
	h := fastHasher()
	s := local.New(repo, h)
	u := seedUser(t, repo, h, "alice@example.com", "Password123!")
	repo.byID[u.ID].PasswordVer = 7
	p, err := s.Authenticate(context.Background(), "alice@example.com", "Password123!")
	if err != nil {
		t.Fatal(err)
	}
	if p.PasswordVer != 7 {
		t.Fatalf("PasswordVer = %d, want 7", p.PasswordVer)
	}
}

// failingUsers wraps memUsers and fails selected writes.
type failingUsers struct {
	*memUsers
	incrementErr, resetErr, updateErr error
}

func (f *failingUsers) IncrementFailedLogin(ctx context.Context, id string, lockUntil time.Time) (int, error) {
	if f.incrementErr != nil {
		return 0, f.incrementErr
	}
	return f.memUsers.IncrementFailedLogin(ctx, id, lockUntil)
}

func (f *failingUsers) ResetFailedLogin(ctx context.Context, id string) error {
	if f.resetErr != nil {
		return f.resetErr
	}
	return f.memUsers.ResetFailedLogin(ctx, id)
}

func (f *failingUsers) UpdatePasswordHash(ctx context.Context, id, hash string, version int) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	return f.memUsers.UpdatePasswordHash(ctx, id, hash, version)
}

// If the failed-login counter cannot be written the lockout is not in
// effect; reporting a plain wrong password would hide that brute-force
// protection is down.
func TestAuthenticate_CounterWriteFailureIsReturned(t *testing.T) {
	boom := errors.New("db down")
	repo := &failingUsers{memUsers: newMemUsers(), incrementErr: boom}
	h := fastHasher()
	seedUser(t, repo.memUsers, h, "alice@example.com", "Password123!")
	s := local.New(repo, h)
	_, err := s.Authenticate(context.Background(), "alice@example.com", "wrong")
	if !errors.Is(err, boom) {
		t.Fatalf("expected the store error, got %v", err)
	}
}

// Housekeeping after a correct password must not fail the login, but must
// not vanish either.
func TestAuthenticate_HousekeepingErrorsReachHandler(t *testing.T) {
	resetErr, updateErr := errors.New("reset failed"), errors.New("update failed")
	repo := &failingUsers{memUsers: newMemUsers(), resetErr: resetErr, updateErr: updateErr}
	weak := password.NewHasher(password.WithArgon2Params(password.Argon2Params{
		Memory: 4 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}))
	seedUser(t, repo.memUsers, weak, "alice@example.com", "Password123!")

	var got []error
	s := local.New(repo, fastHasher(), local.WithErrorHandler(func(_ context.Context, err error) { got = append(got, err) }))
	if _, err := s.Authenticate(context.Background(), "alice@example.com", "Password123!"); err != nil {
		t.Fatalf("login must succeed: %v", err)
	}
	if len(got) != 2 || !errors.Is(got[0], resetErr) || !errors.Is(got[1], updateErr) {
		t.Fatalf("handler got %v, want reset and update errors", got)
	}
}
