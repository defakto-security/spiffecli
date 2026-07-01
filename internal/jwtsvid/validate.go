package jwtsvid

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func ValidateToken(ctx context.Context, token string, jwtBundles jwtbundle.Source, audience []string) (spiffeid.ID, map[string]interface{}, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return spiffeid.ID{}, nil, errors.New("unable to parse JWT token")
	}

	if len(tok.Headers) != 1 {
		return spiffeid.ID{}, nil, errors.Errorf("expected a single token header; got %d", len(tok.Headers))
	}

	// Make sure it has an algorithm supported by JWT-SVID
	alg := tok.Headers[0].Algorithm
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512:
	default:
		return spiffeid.ID{}, nil, errors.Errorf("unsupported token signature algorithm %q", alg)
	}

	// Obtain the key ID from the header
	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return spiffeid.ID{}, nil, errors.New("token header missing key id")
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID. We'll verify the signature on the claims below
	// when creating the generic map of claims that we return to the caller.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return spiffeid.ID{}, nil, errors.Wrap(err, "parsing unverified claims")
	}
	if claims.Subject == "" {
		return spiffeid.ID{}, nil, errors.New("token missing subject claim")
	}
	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return spiffeid.ID{}, nil, errors.Errorf("token has in invalid subject claim: %v", err)
	}

	td := spiffeID.TrustDomain()

	bundle, err := jwtBundles.GetJWTBundleForTrustDomain(td)
	if err != nil {
		return spiffeid.ID{}, nil, errors.Errorf("no keys found for trust domain %q", td)
	}

	key, found := bundle.FindJWTAuthority(keyID)
	if !found {
		return spiffeid.ID{}, nil, errors.Errorf("public key %q not found in trust domain %q", keyID, td)
	}

	// Now obtain the generic claims map verified using the obtained key
	claimsMap := make(map[string]interface{})
	if err := tok.Claims(key, &claimsMap); err != nil {
		return spiffeid.ID{}, nil, errors.Wrap(err, "parsing verified claims")
	}

	// Now that the signature over the claims has been verified, validate the
	// standard claims.
	if err := claims.Validate(jwt.Expected{
		Audience: audience,
		Time:     time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch {
		case errors.Is(err, jwt.ErrExpired):
			err = errors.New("token has expired")
		case errors.Is(err, jwt.ErrInvalidAudience):
			err = errors.Errorf("expected audience in %q (audience=%q)", audience, claims.Audience)
		default:
			err = errors.Wrap(err, "validating claims")
		}
		return spiffeid.ID{}, nil, err
	}

	return spiffeID, claimsMap, nil
}
