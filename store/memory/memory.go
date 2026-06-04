// Package memory is an in-memory reference implementation of every store
// interface in github.com/yurii-bondar/multipass/store.
//
// It is suitable for tests, examples, and single-process demo apps. It is
// NOT suitable for production: data is lost on restart, and there is no
// horizontal scalability across replicas. For real deployments, plug in a
// Redis or SQL adapter that satisfies the same interfaces.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/yurii-bondar/multipass/store"
)

// ----- SessionStore --------------------------------------------------------

type SessionStore struct {
	mu   sync.RWMutex
	data map[string]sessionEntry
}

type sessionEntry struct {
	data       store.SessionData
	expiresAt  time.Time
}

func NewSessionStore() *SessionStore {
	return &SessionStore{data: make(map[string]sessionEntry)}
}

func (s *SessionStore) Save(_ context.Context, sid string, d store.SessionData, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[sid] = sessionEntry{data: d, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *SessionStore) Get(_ context.Context, sid string) (*store.SessionData, error) {
	s.mu.RLock()
	e, ok := s.data[sid]
	s.mu.RUnlock()
	if !ok {
		return nil, store.ErrNotFound
	}
	if time.Now().After(e.expiresAt) {
		s.mu.Lock()
		delete(s.data, sid)
		s.mu.Unlock()
		return nil, store.ErrNotFound
	}
	cp := e.data
	return &cp, nil
}

func (s *SessionStore) Touch(_ context.Context, sid string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[sid]
	if !ok {
		return store.ErrNotFound
	}
	e.data.LastSeen = time.Now()
	e.expiresAt = time.Now().Add(ttl)
	s.data[sid] = e
	return nil
}

func (s *SessionStore) Delete(_ context.Context, sid string) error {
	s.mu.Lock()
	delete(s.data, sid)
	s.mu.Unlock()
	return nil
}

func (s *SessionStore) DeleteByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, e := range s.data {
		if e.data.UserID == userID {
			delete(s.data, sid)
		}
	}
	return nil
}

// ----- Blacklist -----------------------------------------------------------

type Blacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time
}

func NewBlacklist() *Blacklist { return &Blacklist{entries: make(map[string]time.Time)} }

func (b *Blacklist) Add(_ context.Context, jti string, expiresAt time.Time) error {
	b.mu.Lock()
	b.entries[jti] = expiresAt
	b.mu.Unlock()
	return nil
}

func (b *Blacklist) Has(_ context.Context, jti string) (bool, error) {
	b.mu.RLock()
	exp, ok := b.entries[jti]
	b.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if time.Now().After(exp) {
		b.mu.Lock()
		delete(b.entries, jti)
		b.mu.Unlock()
		return false, nil
	}
	return true, nil
}

// ----- RefreshStore --------------------------------------------------------

type RefreshStore struct {
	mu      sync.Mutex
	byJTI   map[string]store.RefreshRecord
}

func NewRefreshStore() *RefreshStore {
	return &RefreshStore{byJTI: make(map[string]store.RefreshRecord)}
}

func (r *RefreshStore) Save(_ context.Context, rec store.RefreshRecord) error {
	r.mu.Lock()
	r.byJTI[rec.JTI] = rec
	r.mu.Unlock()
	return nil
}

func (r *RefreshStore) RotateAndCheck(
	_ context.Context, oldJTI, newJTI string, newExpiresAt time.Time,
) (store.RefreshRecord, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.byJTI[oldJTI]
	if !ok {
		return store.RefreshRecord{}, false, store.ErrNotFound
	}
	if time.Now().After(old.ExpiresAt) {
		return old, false, store.ErrNotFound
	}
	if old.Used {
		return old, true, nil // REUSE
	}
	old.Used = true
	r.byJTI[oldJTI] = old
	r.byJTI[newJTI] = store.RefreshRecord{
		JTI:       newJTI,
		UserID:    old.UserID,
		FamilyID:  old.FamilyID,
		IssuedAt:  time.Now(),
		ExpiresAt: newExpiresAt,
	}
	return old, false, nil
}

func (r *RefreshStore) Revoke(_ context.Context, jti string) error {
	r.mu.Lock()
	delete(r.byJTI, jti)
	r.mu.Unlock()
	return nil
}

func (r *RefreshStore) KillFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for jti, rec := range r.byJTI {
		if rec.FamilyID == familyID {
			delete(r.byJTI, jti)
		}
	}
	return nil
}

func (r *RefreshStore) KillUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for jti, rec := range r.byJTI {
		if rec.UserID == userID {
			delete(r.byJTI, jti)
		}
	}
	return nil
}

// ----- OTPStore ------------------------------------------------------------

type OTPStore struct {
	mu      sync.Mutex
	entries map[string]otpEntry
}

type otpEntry struct {
	payload   store.OTPPayload
	expiresAt time.Time
}

func NewOTPStore() *OTPStore { return &OTPStore{entries: make(map[string]otpEntry)} }

func (o *OTPStore) Save(_ context.Context, code string, p store.OTPPayload, ttl time.Duration) error {
	o.mu.Lock()
	o.entries[code] = otpEntry{payload: p, expiresAt: time.Now().Add(ttl)}
	o.mu.Unlock()
	return nil
}

func (o *OTPStore) Consume(_ context.Context, code string) (*store.OTPPayload, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.entries[code]
	if !ok {
		return nil, store.ErrNotFound
	}
	delete(o.entries, code) // single-use: delete-on-read
	if time.Now().After(e.expiresAt) {
		return nil, store.ErrNotFound
	}
	cp := e.payload
	return &cp, nil
}
