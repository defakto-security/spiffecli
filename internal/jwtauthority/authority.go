package jwtauthority

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/cryptosigner"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/defakto-security/spiffecli/internal/cryptoutil"
)

var (
	ErrInvalidParam = errors.New("invalid parameter")
)

type SVIDParams struct {
	SPIFFEID spiffeid.ID
	Audience []string
	TTL      time.Duration
}

type Option func(*Authority)

func WithClock(clk clock.Clock) Option {
	return func(a *Authority) {
		a.clk = clk
	}
}

type Authority struct {
	signer    jose.Signer
	clk       clock.Clock
	issuer    string
	expiresAt time.Time
}

func New(keyID string, key crypto.Signer, issuer string, expiresAt time.Time, opts ...Option) (*Authority, error) {
	switch {
	case keyID == "":
		return nil, errors.New("keyID is required")
	case key == nil:
		return nil, errors.New("key is required")
	case expiresAt.IsZero():
		return nil, errors.New("expiresAt is required")
	}

	alg, err := cryptoutil.JoseAlgFromPublicKey(key.Public())
	if err != nil {
		return nil, errors.Wrap(err, "determining algorithm")
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(key),
				KeyID: keyID,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return nil, errors.Wrap(err, "creating JWT-SVID signer")
	}

	a := &Authority{
		signer:    signer,
		issuer:    issuer,
		expiresAt: expiresAt,
	}
	for _, opt := range opts {
		opt(a)
	}

	return a, nil
}

func (a *Authority) MintJWTSVID(params SVIDParams) (string, error) {
	switch {
	case params.SPIFFEID.IsZero():
		return "", errors.Wrap(ErrInvalidParam, "SPIFFEID unset")
	case len(params.Audience) == 0:
		return "", errors.Wrap(ErrInvalidParam, "audience unset")
	case hasEmptyAudience(params.Audience):
		return "", errors.Wrap(ErrInvalidParam, "audience has an empty value")
	case params.TTL <= 0:
		return "", errors.Wrap(ErrInvalidParam, "TTL unset or negative")
	}

	now := a.clk.Now()

	expiry, err := determineExpiry(now, params.TTL, a.expiresAt)
	if err != nil {
		return "", err
	}

	jti, err := generateJTI()
	if err != nil {
		return "", errors.Wrap(err, "generating JTI")
	}

	claims := jwt.Claims{
		Issuer:   a.issuer,
		Subject:  params.SPIFFEID.String(),
		Expiry:   jwt.NewNumericDate(expiry),
		Audience: params.Audience,
		IssuedAt: jwt.NewNumericDate(now),
		ID:       jti,
	}

	token, err := jwt.Signed(a.signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", errors.Wrap(err, "signing JWT-SVID")
	}

	return token, nil
}

func determineExpiry(now time.Time, ttl time.Duration, expirationCap time.Time) (notAfter time.Time, err error) {
	if !now.Before(expirationCap) {
		return time.Time{}, errors.New("authority is expired")
	}
	notAfter = now.Add(ttl)
	if notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notAfter, nil
}

func hasEmptyAudience(aundience []string) bool {
	for _, v := range aundience {
		if v == "" {
			return true
		}
	}
	return false
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
