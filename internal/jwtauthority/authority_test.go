package jwtauthority_test

import (
	"context"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/jwtauthority"
	"github.com/defakto-security/spiffecli/internal/jwtsvid"
	"github.com/defakto-security/spiffecli/internal/test/testauthority"
	"github.com/defakto-security/spiffecli/internal/test/testclock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	authority    = testauthority.New("domain.test")
	keyID, key   = authority.JWTAuthority()
	bundle       = authority.Bundle()
	workloadID   = spiffeid.RequireFromString("spiffe://domain.test/foo")
	authorityTTL = time.Hour
	svidTTL      = time.Minute * 5
	issuer       = "ISSUER"
	audience     = []string{"FOO"}
)

func TestNew(t *testing.T) {
	expiresAt := time.Now().Add(authorityTTL)

	_, err := jwtauthority.New("", key, "", expiresAt)
	require.EqualError(t, err, "keyID is required")

	_, err = jwtauthority.New(keyID, nil, "", expiresAt)
	require.EqualError(t, err, "key is required")

	_, err = jwtauthority.New(keyID, key, "", time.Time{})
	require.EqualError(t, err, "expiresAt is required")
}

func TestBadParams(t *testing.T) {
	expiresAt := time.Now().Add(authorityTTL)
	authority, err := jwtauthority.New(keyID, key, issuer, expiresAt)
	require.NoError(t, err)

	assertBad := func(expectErr string, fn func(*jwtauthority.SVIDParams)) {
		t.Helper()
		params := svidParams()
		fn(&params)
		_, err = authority.MintJWTSVID(params)
		assert.EqualError(t, err, expectErr+": invalid parameter")
	}

	assertBad("SPIFFEID unset", func(params *jwtauthority.SVIDParams) {
		params.SPIFFEID = spiffeid.ID{}
	})

	assertBad("audience unset", func(params *jwtauthority.SVIDParams) {
		params.Audience = nil
	})

	assertBad("audience has an empty value", func(params *jwtauthority.SVIDParams) {
		params.Audience = []string{"", "ASDF"}
	})

	assertBad("TTL unset or negative", func(params *jwtauthority.SVIDParams) {
		params.TTL = 0
	})

	assertBad("TTL unset or negative", func(params *jwtauthority.SVIDParams) {
		params.TTL = -1
	})
}

func TestExpiredAuthority(t *testing.T) {
	clk := testclock.New()
	authority, err := jwtauthority.New(keyID, key, issuer, clk.Now(), jwtauthority.WithClock(clk.Clock()))
	require.NoError(t, err)

	_, err = authority.MintJWTSVID(svidParams())
	require.EqualError(t, err, "authority is expired")
}

func TestMintAndVerify(t *testing.T) {
	clk := testclock.New()

	authorityExpiresAt := clk.Now().Add(authorityTTL)

	iat := clk.Now()
	exp := iat.Add(svidTTL)

	mintAndVerify := func(t *testing.T, params jwtauthority.SVIDParams, expectExp time.Time) {
		authority, err := jwtauthority.New(keyID, key, issuer, authorityExpiresAt, jwtauthority.WithClock(clk.Clock()))
		require.NoError(t, err)

		token, err := authority.MintJWTSVID(params)
		require.NoError(t, err)

		tokenID, claims, err := jwtsvid.ValidateToken(context.Background(), token, bundle, audience)
		require.NoError(t, err)

		expectClaims := map[string]interface{}{
			"iss": issuer,
			"aud": "FOO",
			"sub": workloadID.String(),
			"exp": float64(expectExp.Unix()),
			"iat": float64(iat.Unix()),
		}

		// Verify JTI separately, since it is randomly generated.
		jti, ok := claims["jti"]
		if assert.True(t, ok, "missing JTI") {
			assert.NotEmpty(t, jti, "JTI empty")
		}
		delete(claims, "jti")

		assert.Equal(t, workloadID, tokenID)
		assert.Equal(t, expectClaims, claims)
	}

	t.Run("SVID lifetime shorter than authority", func(t *testing.T) {
		mintAndVerify(t, svidParams(), exp)
	})

	t.Run("SVID lifetime longer than authority", func(t *testing.T) {
		params := svidParams()
		params.TTL = authorityTTL + time.Hour
		mintAndVerify(t, params, authorityExpiresAt)
	})
}

func svidParams() jwtauthority.SVIDParams {
	return jwtauthority.SVIDParams{
		SPIFFEID: workloadID,
		Audience: audience,
		TTL:      svidTTL,
	}
}
