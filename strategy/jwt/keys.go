package jwt

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Algorithm is the JWS signing algorithm used by the strategy. Only safe,
// modern algorithms are accepted. The infamous "none" pseudo-algorithm is
// rejected at parse-time (see Strategy.parser below).
type Algorithm string

const (
	// AlgEdDSA uses Ed25519 keys. Default; small keys, fast, no nonce.
	AlgEdDSA Algorithm = "EdDSA"
	// AlgRS256 uses RSA-SHA256. Use when integrating with ecosystems that
	// require RSA (most legacy IdP).
	AlgRS256 Algorithm = "RS256"
	// AlgHS256 uses HMAC-SHA256 with a shared secret. Suitable only for
	// monolithic deployments where signer and verifier share a secret.
	AlgHS256 Algorithm = "HS256"
)

func (a Algorithm) signingMethod() (jwtv5.SigningMethod, error) {
	switch a {
	case AlgEdDSA:
		return jwtv5.SigningMethodEdDSA, nil
	case AlgRS256:
		return jwtv5.SigningMethodRS256, nil
	case AlgHS256:
		return jwtv5.SigningMethodHS256, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", a)
	}
}

// Key bundles a private/public pair tagged with a key id (kid). Multiple keys
// can be active simultaneously: one is "current" (used for signing), the
// others are kept around for verifying tokens that were signed before the
// last rotation.
type Key struct {
	KID  string
	Alg  Algorithm
	Priv crypto.PrivateKey // ed25519.PrivateKey, *rsa.PrivateKey, []byte (HS*)
	Pub  crypto.PublicKey  // ed25519.PublicKey, *rsa.PublicKey, []byte (HS*)
}

// KeyProvider supplies signing keys to the strategy.
//
//	Current() returns the key used for signing newly issued tokens.
//	ByKID(kid) returns a key for verifying an incoming token; if the token
//	  has no kid, implementations may fall back to Current() (we only do so
//	  when there is exactly one configured key, otherwise it is a security
//	  smell).
//
// Implementations MUST be safe for concurrent use and SHOULD support hot
// rotation: the application can swap the "current" key without restart, but
// kept-around keys must still verify until they are explicitly removed.
type KeyProvider interface {
	Current() (Key, error)
	ByKID(kid string) (Key, error)
}

// StaticKeyProvider returns a single static key. Convenient for tests and
// small deployments. For rolling key rotation, supply a custom KeyProvider
// (e.g. backed by a secret manager).
type StaticKeyProvider struct{ K Key }

func (p StaticKeyProvider) Current() (Key, error) { return p.K, nil }
func (p StaticKeyProvider) ByKID(kid string) (Key, error) {
	if kid == "" || kid == p.K.KID {
		return p.K, nil
	}
	return Key{}, fmt.Errorf("jwt: unknown kid %q", kid)
}

// MultiKeyProvider supports rolling rotation: any number of keys may verify,
// the first registered is used to sign unless SetCurrent has been called.
// All methods are safe for concurrent use.
type MultiKeyProvider struct {
	mu        sync.RWMutex
	keys      map[string]Key
	currentID string
}

func NewMultiKeyProvider(current Key, others ...Key) *MultiKeyProvider {
	m := &MultiKeyProvider{keys: map[string]Key{current.KID: current}, currentID: current.KID}
	for _, k := range others {
		m.keys[k.KID] = k
	}
	return m
}

func (m *MultiKeyProvider) Current() (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[m.currentID]
	if !ok {
		return Key{}, errors.New("jwt: no current key set")
	}
	return k, nil
}

func (m *MultiKeyProvider) ByKID(kid string) (Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k, ok := m.keys[kid]
	if !ok {
		return Key{}, fmt.Errorf("jwt: unknown kid %q", kid)
	}
	return k, nil
}

// SetCurrent switches the signing key by kid. The previous current key
// remains available for verification.
func (m *MultiKeyProvider) SetCurrent(kid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[kid]; !ok {
		return fmt.Errorf("jwt: unknown kid %q", kid)
	}
	m.currentID = kid
	return nil
}

// AddKey registers a new key; useful when rolling in a successor before
// promoting it via SetCurrent.
func (m *MultiKeyProvider) AddKey(k Key) {
	m.mu.Lock()
	m.keys[k.KID] = k
	m.mu.Unlock()
}

// RemoveKey removes a key. Tokens signed with it will no longer verify.
func (m *MultiKeyProvider) RemoveKey(kid string) {
	m.mu.Lock()
	delete(m.keys, kid)
	m.mu.Unlock()
}

// signKeyOf returns the value passed to jwt-go's SignedString for the given
// algorithm. The shape that library expects depends on the algorithm.
func signKeyOf(k Key) (any, error) {
	switch k.Alg {
	case AlgEdDSA:
		priv, ok := k.Priv.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: EdDSA: Priv must be ed25519.PrivateKey")
		}
		return priv, nil
	case AlgRS256:
		priv, ok := k.Priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("jwt: RS256: Priv must be *rsa.PrivateKey")
		}
		return priv, nil
	case AlgHS256:
		secret, ok := k.Priv.([]byte)
		if !ok {
			return nil, errors.New("jwt: HS256: Priv must be []byte")
		}
		if len(secret) < 32 {
			return nil, errors.New("jwt: HS256: secret must be at least 32 bytes")
		}
		return secret, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", k.Alg)
	}
}

// verifyKeyOf returns the value jwt-go uses for signature verification.
func verifyKeyOf(k Key) (any, error) {
	switch k.Alg {
	case AlgEdDSA:
		pub, ok := k.Pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("jwt: EdDSA: Pub must be ed25519.PublicKey")
		}
		return pub, nil
	case AlgRS256:
		pub, ok := k.Pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwt: RS256: Pub must be *rsa.PublicKey")
		}
		return pub, nil
	case AlgHS256:
		secret, ok := k.Pub.([]byte)
		if !ok {
			// HMAC: same secret signs and verifies; allow Pub == nil and
			// fall back to Priv for convenience.
			b, okp := k.Priv.([]byte)
			if !okp {
				return nil, errors.New("jwt: HS256: Pub/Priv must be []byte")
			}
			return b, nil
		}
		return secret, nil
	default:
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", k.Alg)
	}
}
