package multipass

import "time"

// Principal is the authenticated identity returned by a successful Verify
// call. It is intentionally minimal; strategy-specific data lives in Extra.
type Principal struct {
	UserID string
	Email  string
	Roles  []string

	// Extra carries strategy-specific metadata that does not fit the common
	// fields (e.g. API-key scopes, OAuth provider name, MFA status).
	Extra map[string]any

	// StrategyName is the Name() of the strategy that produced this Principal.
	StrategyName string

	// TokenID identifies the credential used for this request:
	//   - JWT  : jti
	//   - PASETO: jti (or footer-id)
	//   - Session: SID
	//   - API Key: key id / prefix
	// Empty for stateless single-shot verifications.
	TokenID string

	// IssuedAt and ExpiresAt are populated when the underlying credential
	// carries timestamps. They are advisory: the strategy is responsible
	// for enforcing expiry.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Credentials is the artefact returned to the caller after a successful
// Issue / Login / Refresh.
//
// For stateful strategies (Session) only Access (== SID) is set.
// For token-pair strategies (JWT, PASETO) both Access and Refresh are set.
// For API keys Access is the raw key (returned only on creation; the server
// stores a hash and cannot recover the key later).
type Credentials struct {
	Access  string
	Refresh string

	// TokenType is the value to put after `Authorization: ` for HTTP usage,
	// or "Session" / "API-Key" for non-bearer credentials.
	TokenType string

	AccessExpiry  time.Time
	RefreshExpiry time.Time

	// Subject is the UserID embedded in the credential. Caller convenience.
	Subject string
}
