package jwtinspect

import (
	"fmt"

	"github.com/go-jose/go-jose/v4/jwt"
)

// TODO: At some point we'll want to add support for encrypted JWTs, as well as
// "none" JWTs. We'd want to detect either of these. For encrypted JWTs the user
// would have to pass a key.
func DeserializeJwt(serialized string) (*jwt.JSONWebToken, error) {
	tok, err := jwt.ParseSigned(serialized, AllSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT")
	}
	return tok, nil
}
