# multipass

A pluggable, framework-agnostic authentication library for Go, conceptually
inspired by Passport.js. Every authentication method (JWT, PASETO, opaque
sessions, API keys, magic links / OTP, TOTP, Passkeys/WebAuthn) is a
`Strategy` that satisfies a single small interface and is registered on a
`Service`. Any issuing strategy can additionally be wrapped with
`multipass.RequireTwoFactor` to demand a second factor before it mints a
credential.

## Design rules

1. The library never imports a database driver, a cache client, or an HTTP
   framework. All side-effects go through interfaces that the host
   application implements.
2. The core works with raw strings (token, sid, api key). HTTP plumbing is
   opt-in and lives under `transport/`.
3. Strategies expose the same triple — `Issue` / `Verify` / `Revoke` — so
   they are interchangeable from the business-logic point of view. Optional
   capabilities (`Refresh`, `RevokeAllForUser`) are advertised via narrow
   interfaces that callers detect with a type assertion.

## Strategy matrix

| Strategy | Where state lives | Refresh? | RevokeAll? | Best for |
| --- | --- | --- | --- | --- |
| `local` | in user repo | n/a | n/a | email + password verifier; pair with a token strategy |
| `jwt` | client (+ optional refresh store) | yes | yes (refresh store) | distributed services, stateless API |
| `paseto` | client (+ optional refresh store) | yes | yes (refresh store) | new APIs that want JWT semantics without JWT pitfalls |
| `session` | server (`SessionStore`) | n/a (rolling) | yes | classic web apps, cookie-based auth |
| `apikey` | server (`KeyStore`) | n/a | yes | programmatic access, M2M |
| `magiclink` | server (`OTPStore`) | n/a | n/a | passwordless email/SMS login |
| `totp` | per-user secret | n/a | n/a | second factor on top of any other strategy |
| `webauthn` | server (`CredentialStore` + `OTPStore` for challenges) | n/a | yes | Passkeys/FIDO2, phishing-resistant login, second factor |

## Two-factor: `multipass.RequireTwoFactor`

Any issuing strategy (`jwt`, `paseto`, `session`, `apikey`, `webauthn`, ...)
can be wrapped at `Register` time so it demands a second factor before
minting a credential — one decorator, not a per-strategy `2FA: true` flag,
since every strategy already exposes the same `Issue`/`Verify`/`Revoke`
triple:

```go
totpStore := myTOTPSecretStore() // TOTP secrets, keyed by user id
totpGuard := myTOTPGuard()       // store.TOTPGuard: replay + attempt limit
totp, _ := magiclink.NewTOTP(totpStore, totpGuard)

gate, err := multipass.RequireTwoFactor(jwtStrategy, totp, pendingStore, // store.OTPStore
    multipass.WithRequirement(multipass.TwoFactorRequirementFunc(
        func(ctx context.Context, userID string) (bool, error) {
            u, err := users.GetByID(ctx, userID)
            if err != nil {
                return false, err
            }
            return u.MFASecret != "", nil // only users enrolled in 2FA are gated
        },
    )),
)
svc.Register(gate)
svc.Register(local.New(users, hasher)) // primary factor, left unwrapped
```

The gate keeps the wrapped strategy's name, so `svc.Login(ctx, "local",
"jwt", email, password)` still works. For an enrolled user it mints nothing:
it stores the authenticated principal as a pending login and returns a
`*multipass.TwoFactorPendingError` (matches `ErrTwoFactorRequired`) carrying
a single-use, short-lived token. Hand the token to the client, then:

```go
var pending *multipass.TwoFactorPendingError
if errors.As(err, &pending) {
    // ... prompt for the code, then in the next request:
    creds, err := svc.CompleteTwoFactor(ctx, "jwt", pending.Token, code)
}
```

The second factor is always checked against the user stored in the pending
login — never one supplied by the client — so the code step cannot be
reached without passing the password step first. Wrong codes are allowed
`WithMaxAttempts` times (default 3) before the pending login is discarded.
`webauthn.Strategy` implements `multipass.SecondFactor` as well, so a passkey
can be the second factor instead of TOTP.

## Installation

```bash
go get github.com/yurii-bondar/multipass
```

## Quick start: JWT

```go
package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "log"
    "net/http"
    "time"

    "github.com/yurii-bondar/multipass"
    "github.com/yurii-bondar/multipass/password"
    "github.com/yurii-bondar/multipass/store/memory"
    "github.com/yurii-bondar/multipass/strategy/jwt"
    "github.com/yurii-bondar/multipass/strategy/local"
    "github.com/yurii-bondar/multipass/transport/extract"
    transport "github.com/yurii-bondar/multipass/transport/nethttp"
)

func main() {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    keys := jwt.StaticKeyProvider{K: jwt.Key{KID: "k1", Alg: jwt.AlgEdDSA, Priv: priv, Pub: pub}}

    js, _ := jwt.New(keys,
        jwt.WithIssuer("example"),
        jwt.WithAudience("example.api"),
        jwt.WithAccessTTL(15*time.Minute),
        jwt.WithRefreshTTL(30*24*time.Hour),
        jwt.WithBlacklist(memory.NewBlacklist()),
        jwt.WithRefreshStore(memory.NewRefreshStore()),
    )

    users := myUserRepo() // your impl of multipass.UserRepository
    svc := multipass.New(users)
    svc.Register(js)
    svc.Register(local.New(users, password.NewHasher()))

    mw := transport.New(svc, jwt.Name, extract.BearerFromHeader)

    mux := http.NewServeMux()
    mux.Handle("/me", mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        p := transport.MustFromContext(r.Context())
        _, _ = w.Write([]byte("hi " + p.UserID))
    })))
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Key rotation (JWT)

`MultiKeyProvider` supports zero-downtime key rotation and is safe for
concurrent use (all methods are guarded by a read/write mutex):

```go
mp := jwt.NewMultiKeyProvider(oldKey)
mp.AddKey(newKey)          // register successor (still verifying with oldKey)
mp.SetCurrent(newKey.KID)  // start signing with newKey; oldKey still verifies
// ... after all old tokens expire:
mp.RemoveKey(oldKey.KID)   // drop old key; tokens signed with it stop verifying
```

## JWT best practices baked in

- `EdDSA` is the default algorithm. `RS256` and `HS256` are opt-in.
- The infamous `alg=none` is rejected by the parser
  (`jwt.WithValidMethods` is set with the configured algorithm only).
- Access tokens are short-lived (default 15 min) and carry `iss`, `sub`,
  `aud`, `exp`, `iat`, `nbf`, `jti`.
- Refresh tokens are stateful: each refresh rotates the token and atomically
  marks the old one as used. Replaying an already-used refresh kills the
  whole token family — every device of that user is logged out.
- Refresh tokens carry the identity claims (email, roles, `pwd_ver`), so
  they survive any number of rotations. `WithUserLookup` makes every refresh
  re-read the user: a disabled, deleted or password-changed account (bumped
  `User.PasswordVer`) kills the token family, and role changes take effect
  at the next refresh instead of the next login.
- A `Blacklist` lets you revoke individual access tokens before they expire
  naturally; entries are pruned automatically.
- Key rotation is supported via `KeyProvider` (multiple `KID`s verify, one
  signs; promote any of them with `MultiKeyProvider.SetCurrent`).

## Storage adapters

The library never imports Redis, Postgres, or any other store. Implement
the relevant interface from `store/store.go` and pass it in:

```go
type myRedisSessionStore struct{ rdb *redis.Client }

func (s *myRedisSessionStore) Save(ctx context.Context, sid string, d store.SessionData, ttl time.Duration) error {
    blob, _ := json.Marshal(d)
    return s.rdb.Set(ctx, "sess:"+sid, blob, ttl).Err()
}
// Get / Touch / Delete / DeleteByUser left as an exercise.
```

In-memory reference implementations live under `store/memory/` and are
useful for tests and examples — never for production.

## Examples

Every strategy in the matrix above has a runnable, self-contained example
(each is `package main`, in-memory storage, state lost on restart — wire
real adapters in production):

- [`examples/jwt`](examples/jwt) — `local` + `jwt`: signup/login/refresh/logout
  over Bearer tokens.
- [`examples/session`](examples/session) — `local` + `session`: cookie-based,
  opaque server-side sessions.
- [`examples/paseto`](examples/paseto) — `local` + `paseto` (v4.public): same
  shape as the JWT example, no `alg` field, no algorithm-confusion surface.
- [`examples/magiclink`](examples/magiclink) — fully passwordless login: a
  one-time link "sent" (printed to stdout) creates the account on first sight
  and a `jwt` is issued once the link is followed.
- [`examples/apikey`](examples/multi) — covered inside `examples/multi`'s
  `/m2m` routes: an authenticated user mints a hashed API key for
  machine-to-machine calls.
- [`examples/multi`](examples/multi) — one `Service`, three transports: JWT
  for `/api`, sessions for `/web`, API keys for `/m2m`.
- [`examples/webauthn`](examples/webauthn) — **Passkeys/FIDO2**: a real
  browser demo (open `http://localhost:8080`) that registers and logs in
  with `navigator.credentials` — Touch ID/Windows Hello, a phone via the QR
  "hybrid" flow, or a USB security key — then issues a `jwt`.
- [`examples/twofactor`](examples/twofactor) — **2FA**: `multipass.RequireTwoFactor`
  gating `jwt` behind a standard RFC 6238 TOTP code, compatible with Aegis,
  Google/Microsoft Authenticator, 1Password, etc.

Run any of them:

```bash
go run ./examples/jwt
```

`examples/webauthn` is the one you open in an actual browser rather than
curl — WebAuthn ceremonies only exist there. Every other example is
curl/HTTPie-friendly; see the comment block at the top of each `main.go` for
example requests.

## Security guarantees

- All secrets come from `crypto/rand`; no `math/rand` anywhere.
- Constant-time comparisons (`subtle`) on tokens and password hashes.
- Argon2id by default, OWASP-2024-aligned cost; bcrypt only on read for
  legacy migration.
- Optional server-side pepper for password hashing.
- Anti-enumeration on `local`: identical timing for `user not found` and
  `wrong password`; same `ErrInvalidCredentials` returned in both cases.
- Account lockout after configurable failed-attempt threshold (see note
  below on concurrent failures).
- Single-use OTPs (atomic delete-on-read) for magic links / SMS codes.
  Numeric codes are bound to their recipient (verified as
  `"<recipient>:<code>"`) and verification is rate-limited per recipient.
- TOTP codes are accepted at most once (RFC 6238 §5.2) and verification
  attempts are capped per user (default 5 per 15 min) via `store.TOTPGuard`.
- Cookies built by `transport/cookie` use `HttpOnly`, `Secure`,
  `SameSite=Lax`, and the `__Host-` prefix by default.
- Every operation is `context`-aware: cancellation, deadlines, and
  request-scoped values flow through naturally.
- `MultiKeyProvider` is safe for concurrent use; key rotation via
  `SetCurrent` / `AddKey` / `RemoveKey` can be called from any goroutine
  while active request goroutines are verifying tokens.
- `webauthn` is phishing-resistant by construction: the browser binds every
  signature to the origin that created the credential, so a byte-perfect
  lookalike domain still cannot obtain a valid assertion. Challenges are
  single-use (atomic delete-on-read via `OTPStore`) and TTL-bound.
- `multipass.RequireTwoFactor` lets any issuing strategy be gated behind a
  second factor without touching that strategy's own code. The second step
  is bound to a server-side pending login, so it cannot be reached without
  the primary factor.

### Account lockout under concurrent failures

The lockout logic in the `local` strategy uses the authoritative
post-increment count returned by `UserRepository.IncrementFailedLogin` to
detect when concurrent failures push the counter over the threshold even if
the pre-read count was stale. In that edge case a corrective second call
sets the lock (at the cost of an extra counter increment).

For full atomicity in high-concurrency environments, implement
`IncrementFailedLogin` as a single conditional UPDATE in your database:

```sql
UPDATE users
   SET failed_logins = failed_logins + 1,
       locked_until  = CASE WHEN failed_logins + 1 >= $threshold
                            THEN $lock_until ELSE locked_until END
 WHERE id = $id
RETURNING failed_logins;
```

## Project layout

```
.
├── auth.go             Service, Strategy registry
├── principal.go        Principal, Credentials
├── two_factor.go       TwoFactorGate: wrap any strategy to demand a 2nd factor
├── errors.go           Sentinel errors
├── ports.go            UserRepository, Clock, IDGen
├── password/           Argon2id + bcrypt + pepper
├── store/
│   ├── store.go        SessionStore, Blacklist, RefreshStore, OTPStore, CredentialStore
│   └── memory/         in-memory reference impls
├── strategy/
│   ├── local/          email + password verifier
│   ├── jwt/            EdDSA/RS256/HS256, refresh + reuse detection
│   ├── paseto/         v4.local + v4.public
│   ├── session/        opaque SID, idle + absolute TTL
│   ├── apikey/         hashed API keys, scopes
│   ├── magiclink/      magic links + numeric OTP + TOTP
│   └── webauthn/       Passkeys / FIDO2 registration + login
├── transport/
│   ├── extract/        Bearer / Cookie / Query / API-Key extractors
│   ├── cookie/         secure cookie defaults
│   └── nethttp/        net/http middleware
└── examples/
    ├── jwt/
    ├── session/
    └── multi/
```

## Contract: implementing a UserRepository

```go
type UserRepository interface {
    GetByID(ctx context.Context, id string) (*multipass.User, error)
    GetByEmail(ctx context.Context, email string) (*multipass.User, error)
    Create(ctx context.Context, u *multipass.User) error
    UpdatePasswordHash(ctx context.Context, id, hash string, version int) error
    IncrementFailedLogin(ctx context.Context, id string, lockUntil time.Time) (int, error)
    ResetFailedLogin(ctx context.Context, id string) error
}
```

Return `multipass.ErrUserNotFound` (not `nil, nil`) for missing users — the
strategy uses that to keep timing uniform across hit/miss.

## License

MIT.
