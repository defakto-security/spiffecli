package wlapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

var (
	maxUint128 = getMaxUint128()
	one        = big.NewInt(1)
)

// NewSerialNumber creates a random certificate serial number according to CA/Browser forum spec
// Section 7.1:
// "Effective September 30, 2016, CAs SHALL generate non-sequential Certificate serial numbers greater than
// zero (0) containing at least 64 bits of output from a CSPRNG"
func newSerialNumber() (*big.Int, error) {
	// Creates random integer in range [0,MaxUint128)
	s, err := rand.Int(rand.Reader, maxUint128)
	if err != nil {
		return nil, fmt.Errorf("cannot create random number: %w", err)
	}

	// Adds 1 to return serial number [1,MaxUint128]
	return s.Add(s, one), nil
}

func getMaxUint128() *big.Int {
	max, ok := new(big.Int).SetString("340282366920938463463374607431768211455", 10) // (2^128 − 1)
	if !ok {
		panic("cannot parse value for max unsigned int 128")
	}
	return max
}

func generateKey() (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generating key")
	}
	return key, nil
}

func certsBytes(certs ...*x509.Certificate) (out []byte) {
	for _, cert := range certs {
		out = append(out, cert.Raw...)
	}
	return out
}
