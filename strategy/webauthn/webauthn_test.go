package webauthn_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
	"github.com/yurii-bondar/multipass/store/memory"
	"github.com/yurii-bondar/multipass/strategy/webauthn"
)

const (
	rpID      = "example.com"
	rpOrigin  = "https://example.com"
	rpDisplay = "Example Corp"
)

// userStore is a minimal in-memory webauthn.UserLookup for tests.
type userStore struct {
	byID map[string]*multipass.User
}

func newUserStore(users ...*multipass.User) *userStore {
	s := &userStore{byID: make(map[string]*multipass.User)}
	for _, u := range users {
		s.byID[u.ID] = u
	}
	return s
}

func (s *userStore) GetByID(_ context.Context, id string) (*multipass.User, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, multipass.ErrUserNotFound
	}
	return u, nil
}

func newStrategy(t *testing.T, users webauthn.UserLookup) (*webauthn.Strategy, store.CredentialStore) {
	t.Helper()
	creds := memory.NewCredentialStore()
	otp := memory.NewOTPStore()
	cfg := &gowebauthn.Config{RPID: rpID, RPDisplayName: rpDisplay, RPOrigins: []string{rpOrigin}}
	s, err := webauthn.New(cfg, users, creds, otp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, creds
}

// registerCredential drives a full registration ceremony using a virtual
// (software) authenticator standing in for a real browser + FIDO2 device.
func registerCredential(
	t *testing.T,
	s *webauthn.Strategy,
	u *multipass.User,
	rp virtualwebauthn.RelyingParty,
	auth *virtualwebauthn.Authenticator,
	cred virtualwebauthn.Credential,
) {
	t.Helper()
	ctx := context.Background()

	creation, sessionID, err := s.BeginRegistration(ctx, u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	optJSON, err := json.Marshal(creation)
	if err != nil {
		t.Fatalf("marshal creation options: %v", err)
	}
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(optJSON))
	if err != nil {
		t.Fatalf("ParseAttestationOptions: %v", err)
	}
	if attOpts.RelyingPartyID != rpID {
		t.Fatalf("RelyingPartyID = %q, want %q", attOpts.RelyingPartyID, rpID)
	}
	if attOpts.UserID != u.ID {
		t.Fatalf("UserID = %q, want %q", attOpts.UserID, u.ID)
	}

	attResp := virtualwebauthn.CreateAttestationResponse(rp, *auth, cred, *attOpts)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(attResp))
	req.Header.Set("Content-Type", "application/json")

	rec, err := s.FinishRegistration(ctx, sessionID, "virtual key", req)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if rec.UserID != u.ID {
		t.Fatalf("record.UserID = %q, want %q", rec.UserID, u.ID)
	}
	if rec.Name != "virtual key" {
		t.Fatalf("record.Name = %q, want %q", rec.Name, "virtual key")
	}

	auth.AddCredential(cred)
}

func TestWebAuthn_RegisterAndLogin_KnownUser(t *testing.T) {
	ctx := context.Background()
	u := &multipass.User{ID: "user-1", Email: "alice@example.com"}
	s, creds := newStrategy(t, newUserStore(u))

	rp := virtualwebauthn.RelyingParty{Name: rpDisplay, ID: rpID, Origin: rpOrigin}
	auth := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	registerCredential(t, s, u, rp, &auth, cred)

	assertion, sessionID, err := s.BeginLogin(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	optJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}

	assertResp := virtualwebauthn.CreateAssertionResponse(rp, auth, cred, *assertOpts)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(assertResp))
	req.Header.Set("Content-Type", "application/json")

	p, err := s.FinishLogin(ctx, sessionID, req)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if p.UserID != u.ID {
		t.Errorf("Principal.UserID = %q, want %q", p.UserID, u.ID)
	}
	if p.StrategyName != webauthn.Name {
		t.Errorf("Principal.StrategyName = %q, want %q", p.StrategyName, webauthn.Name)
	}
	wantTokenID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if p.TokenID != wantTokenID {
		t.Errorf("Principal.TokenID = %q, want %q", p.TokenID, wantTokenID)
	}

	// Session must be single-use: replaying it must fail.
	if _, err := s.FinishLogin(ctx, sessionID, req); err == nil {
		t.Fatal("expected replayed session to fail")
	}

	stored, err := creds.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get stored credential: %v", err)
	}
	if stored.Name != "virtual key" {
		t.Errorf("stored.Name = %q, want the friendly name to survive a login (bumpCounter must not clobber it)", stored.Name)
	}
}

func TestWebAuthn_RegisterAndLogin_Discoverable(t *testing.T) {
	ctx := context.Background()
	u := &multipass.User{ID: "user-2", Email: "bob@example.com"}
	s, _ := newStrategy(t, newUserStore(u))

	rp := virtualwebauthn.RelyingParty{Name: rpDisplay, ID: rpID, Origin: rpOrigin}
	auth := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	registerCredential(t, s, u, rp, &auth, cred)
	// A resident/discoverable credential reports the owning user's handle
	// back to the relying party without the caller specifying it upfront.
	auth.Options.UserHandle = []byte(u.ID)

	assertion, sessionID, err := s.BeginDiscoverableLogin(ctx)
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}

	optJSON, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion options: %v", err)
	}
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}

	assertResp := virtualwebauthn.CreateAssertionResponse(rp, auth, cred, *assertOpts)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(assertResp))
	req.Header.Set("Content-Type", "application/json")

	p, err := s.FinishLogin(ctx, sessionID, req)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if p.UserID != u.ID {
		t.Errorf("Principal.UserID = %q, want %q", p.UserID, u.ID)
	}
}

func TestWebAuthn_Verify_JSONEnvelope(t *testing.T) {
	ctx := context.Background()
	u := &multipass.User{ID: "user-3", Email: "carol@example.com"}
	s, _ := newStrategy(t, newUserStore(u))

	rp := virtualwebauthn.RelyingParty{Name: rpDisplay, ID: rpID, Origin: rpOrigin}
	auth := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	registerCredential(t, s, u, rp, &auth, cred)

	assertion, sessionID, err := s.BeginLogin(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	optJSON, _ := json.Marshal(assertion)
	assertOpts, err := virtualwebauthn.ParseAssertionOptions(string(optJSON))
	if err != nil {
		t.Fatalf("ParseAssertionOptions: %v", err)
	}
	assertResp := virtualwebauthn.CreateAssertionResponse(rp, auth, cred, *assertOpts)

	envelope, err := json.Marshal(map[string]any{
		"session_id": sessionID,
		"credential": json.RawMessage(assertResp),
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	p, err := s.Verify(ctx, string(envelope))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.UserID != u.ID {
		t.Errorf("Principal.UserID = %q, want %q", p.UserID, u.ID)
	}
}

func TestWebAuthn_Verify_InvalidEnvelope(t *testing.T) {
	s, _ := newStrategy(t, newUserStore())
	if _, err := s.Verify(context.Background(), "not json"); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid, got %v", err)
	}
	if _, err := s.Verify(context.Background(), `{"session_id":""}`); !errors.Is(err, multipass.ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid for missing session_id, got %v", err)
	}
}

func TestWebAuthn_FinishLogin_UnknownSession(t *testing.T) {
	s, _ := newStrategy(t, newUserStore())
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	if _, err := s.FinishLogin(context.Background(), "nope", req); !errors.Is(err, multipass.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestWebAuthn_Issue_Unsupported(t *testing.T) {
	s, _ := newStrategy(t, newUserStore())
	_, err := s.Issue(context.Background(), multipass.Principal{})
	if !errors.Is(err, multipass.ErrUnsupportedOperation) {
		t.Fatalf("expected ErrUnsupportedOperation, got %v", err)
	}
}

func TestWebAuthn_Revoke_And_RevokeAllForUser(t *testing.T) {
	ctx := context.Background()
	u := &multipass.User{ID: "user-4", Email: "dave@example.com"}
	s, creds := newStrategy(t, newUserStore(u))

	rp := virtualwebauthn.RelyingParty{Name: rpDisplay, ID: rpID, Origin: rpOrigin}
	auth := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerCredential(t, s, u, rp, &auth, cred)

	list, err := s.ListCredentials(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListCredentials = %+v, %v", list, err)
	}

	tokenID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if err := s.Revoke(ctx, tokenID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := creds.Get(ctx, cred.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected credential to be deleted, got err=%v", err)
	}

	// Idempotent: revoking again is not an error.
	if err := s.Revoke(ctx, tokenID); err != nil {
		t.Fatalf("Revoke (idempotent): %v", err)
	}

	// RevokeAllForUser wipes every remaining passkey.
	cred2 := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	registerCredential(t, s, u, rp, &auth, cred2)
	if err := s.RevokeAllForUser(ctx, u.ID); err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if list, err := s.ListCredentials(ctx, u.ID); err != nil || len(list) != 0 {
		t.Fatalf("ListCredentials after RevokeAllForUser = %+v, %v", list, err)
	}
}
