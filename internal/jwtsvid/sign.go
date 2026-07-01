package jwtsvid

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/defakto-security/spiffecli/internal/cryptoutil"
)

type SignerConfig struct {
	Clock clock.Clock

	// Issuer is used as the value of the issuer (iss) claim, if set.
	Issuer string
}

type Signer struct {
	c SignerConfig
}

func NewSigner(config SignerConfig) *Signer {
	return &Signer{
		c: config,
	}
}

func (s *Signer) SignToken(id spiffeid.ID, audience []string, expires time.Time, signer crypto.Signer, kid string) (string, error) {
	audience = pruneEmptyValues(audience)

	if id.IsZero() {
		return "", errors.New("id is required")
	}
	if expires.IsZero() {
		return "", errors.New("expiration is required")
	}
	if len(audience) == 0 {
		return "", errors.New("audience is required")
	}
	if len(kid) == 0 {
		return "", errors.New("kid is required")
	}

	claims := jwt.Claims{
		Subject:  id.String(),
		Issuer:   s.c.Issuer,
		Expiry:   jwt.NewNumericDate(expires),
		Audience: audience,
		IssuedAt: jwt.NewNumericDate(s.c.Clock.Now()),
	}

	alg, err := cryptoutil.JoseAlgFromPublicKey(signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine JOSE algorithm: %v", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %v", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %v", err)
	}

	return signedToken, nil
}

func pruneEmptyValues(values []string) []string {
	pruned := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			pruned = append(pruned, value)
		}
	}
	return pruned
}
