// Package password provides constant-time password hashing and verification.
//
// Argon2id (RFC 9106) is the default and is what every new password hash
// uses. Bcrypt is recognised on read so that legacy hashes from older
// databases still verify; on the next successful login the strategy can
// re-hash with Argon2id by calling Hash again.
//
// All hashes are encoded as PHC-style strings starting with a $-delimited
// algorithm tag, which is how we tell argon2id and bcrypt apart on read:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
//	$2a$12$<bcrypt>...
//
// A server-wide "pepper" (a secret added to the password before hashing)
// is supported but optional. It is HMAC'd into the password so that a
// database leak alone does not enable offline cracking — an attacker must
// also exfiltrate the pepper from the application server.
package password

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Hasher hashes and verifies passwords. The package-level helpers Hash and
// Verify use a default-configured hasher; production code should construct
// its own with NewHasher to inject the pepper.
type Hasher struct {
	pepper []byte
	params Argon2Params
}

// Argon2Params holds the cost parameters fed to argon2.IDKey. The defaults
// (DefaultArgon2Params) follow OWASP 2024 recommendations and target
// roughly 0.5–1.0 s on a modern x86 CPU.
type Argon2Params struct {
	Memory      uint32 // KiB; default 64 MiB
	Iterations  uint32 // default 3
	Parallelism uint8  // default 2
	SaltLength  uint32 // bytes; default 16
	KeyLength   uint32 // bytes; default 32
}

// DefaultArgon2Params returns OWASP-2024-aligned defaults.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Option customises a Hasher.
type Option func(*Hasher)

// WithPepper sets a server-side secret that is HMAC'd into the password
// before hashing. Pass an empty slice to disable.
func WithPepper(pepper []byte) Option { return func(h *Hasher) { h.pepper = pepper } }

// WithArgon2Params overrides the default cost parameters.
func WithArgon2Params(p Argon2Params) Option { return func(h *Hasher) { h.params = p } }

// NewHasher constructs a Hasher.
func NewHasher(opts ...Option) *Hasher {
	h := &Hasher{params: DefaultArgon2Params()}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Hash returns a PHC-encoded argon2id hash of the password.
func (h *Hasher) Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("password: empty password")
	}
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}
	in := h.applyPepper([]byte(password))
	key := argon2.IDKey(in, salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return encodeArgon2id(h.params, salt, key), nil
}

// Verify returns nil when password matches encoded; ErrPasswordMismatch when
// it does not; an error for malformed encoded strings.
//
// On success and when the encoded hash uses a non-default algorithm or
// outdated cost parameters, Verify returns NeedsRehash == true so the
// caller can opportunistically migrate the user to a stronger hash.
func (h *Hasher) Verify(encoded, password string) (needsRehash bool, err error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		params, salt, want, err := decodeArgon2id(encoded)
		if err != nil {
			return false, err
		}
		got := argon2.IDKey(h.applyPepper([]byte(password)),
			salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return false, ErrPasswordMismatch
		}
		needsRehash = paramsWeaker(params, h.params)
		return needsRehash, nil
	case strings.HasPrefix(encoded, "$2a$"), strings.HasPrefix(encoded, "$2b$"), strings.HasPrefix(encoded, "$2y$"):
		if err := bcrypt.CompareHashAndPassword([]byte(encoded), h.applyPepper([]byte(password))); err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				return false, ErrPasswordMismatch
			}
			return false, fmt.Errorf("password: bcrypt verify: %w", err)
		}
		return true, nil // legacy bcrypt -> always rehash to argon2id
	default:
		return false, fmt.Errorf("password: unknown hash format")
	}
}

// FakeVerify performs a hash with the same cost parameters as a real verify
// but against a precomputed dummy hash. It is used by the local strategy to
// keep response time uniform between "user not found" and "wrong password".
func (h *Hasher) FakeVerify(password string) {
	// Best-effort dummy; the result is intentionally discarded.
	_ = argon2.IDKey(h.applyPepper([]byte(password)), dummySalt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
}

func (h *Hasher) applyPepper(in []byte) []byte {
	if len(h.pepper) == 0 {
		return in
	}
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write(in)
	return mac.Sum(nil)
}

// ErrPasswordMismatch is returned by Verify when the password is wrong.
// Strategies translate this to multipass.ErrInvalidCredentials.
var ErrPasswordMismatch = errors.New("password: mismatch")

var dummySalt = []byte("multipass-dummy-salt-16b")

// ----- PHC encoding helpers ------------------------------------------------

func encodeArgon2id(p Argon2Params, salt, key []byte) string {
	b64 := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64(salt), b64(key))
}

func decodeArgon2id(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errors.New("password: malformed argon2id hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("password: bad version: %w", err)
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("password: unsupported argon2 version %d", version)
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("password: bad params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("password: bad salt b64: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("password: bad hash b64: %w", err)
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(hash))
	return p, salt, hash, nil
}

func paramsWeaker(have, want Argon2Params) bool {
	return have.Memory < want.Memory ||
		have.Iterations < want.Iterations ||
		have.Parallelism < want.Parallelism ||
		have.KeyLength < want.KeyLength
}
