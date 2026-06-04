package jwt

import (
	"context"
	"errors"
	"fmt"

	"github.com/yurii-bondar/multipass"
	"github.com/yurii-bondar/multipass/store"
)

// Refresh consumes an opaque refresh JWT and returns a fresh access+refresh
// pair. Implements multipass.Refreshable.
//
// Algorithm:
//
//  1. Parse the refresh token strictly (signature + claims valid, typ ==
//     "refresh"). Reject expired or wrong-type tokens.
//  2. Atomically tell the RefreshStore: rotate this jti, here is the new
//     one. The store either succeeds (token had not been used yet) or
//     reports reused == true.
//  3. On reuse, we are facing a probable token theft: kill the entire
//     family so every existing refresh in this lineage stops working, and
//     return ErrReuseDetected.
//  4. On success, sign a new access token and a new refresh token with the
//     same family id, and return both.
func (s *Strategy) Refresh(ctx context.Context, refresh string) (multipass.Credentials, error) {
	if s.refreshStore == nil {
		return multipass.Credentials{}, fmt.Errorf("%w: jwt.Refresh requires a RefreshStore", multipass.ErrUnsupportedOperation)
	}

	claims, err := s.parse(refresh)
	if err != nil {
		return multipass.Credentials{}, err
	}
	if claims.Type != typRefresh {
		return multipass.Credentials{}, fmt.Errorf("%w: expected refresh token, got %q", multipass.ErrTokenInvalid, claims.Type)
	}
	if claims.ID == "" || claims.FamilyID == "" || claims.Subject == "" {
		return multipass.Credentials{}, fmt.Errorf("%w: refresh missing jti/fid/sub", multipass.ErrTokenInvalid)
	}

	now := s.clock.Now()

	newAccessJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("jwt: gen access jti: %w", err)
	}
	newRefreshJTI, err := s.idgen.NewID()
	if err != nil {
		return multipass.Credentials{}, fmt.Errorf("jwt: gen refresh jti: %w", err)
	}
	newRefreshExp := now.Add(s.refreshTTL)

	rec, reused, err := s.refreshStore.RotateAndCheck(ctx, claims.ID, newRefreshJTI, newRefreshExp)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Either the token was already revoked (logout) or it never
			// existed. Indistinguishable from "invalid" from the client's
			// point of view.
			return multipass.Credentials{}, multipass.ErrTokenRevoked
		}
		return multipass.Credentials{}, fmt.Errorf("jwt: rotate refresh: %w", err)
	}
	if reused {
		// A successor of this token is already in circulation: someone is
		// replaying. Burn the family.
		_ = s.refreshStore.KillFamily(ctx, claims.FamilyID)
		return multipass.Credentials{}, multipass.ErrReuseDetected
	}

	access, accessExp, err := s.signClaims(Claims{
		RegisteredClaims: s.registered(claims.Subject, newAccessJTI, now, now.Add(s.accessTTL)),
		Type:             typAccess,
		Email:            claims.Email,
		Roles:            claims.Roles,
		PwdVer:           claims.PwdVer,
	})
	if err != nil {
		return multipass.Credentials{}, err
	}

	newRefresh, _, err := s.signClaims(Claims{
		RegisteredClaims: s.registered(claims.Subject, newRefreshJTI, now, newRefreshExp),
		Type:             typRefresh,
		FamilyID:         rec.FamilyID,
	})
	if err != nil {
		return multipass.Credentials{}, err
	}

	return multipass.Credentials{
		Access:        access,
		Refresh:       newRefresh,
		TokenType:     "Bearer",
		AccessExpiry:  accessExp,
		RefreshExpiry: newRefreshExp,
		Subject:       claims.Subject,
	}, nil
}
