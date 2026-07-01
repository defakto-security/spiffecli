package testx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// NewThreeLevelSPIFFEChain returns root → intermediate → leaf certificates for a
// canonical SPIFFE SVID hierarchy used by inspect-x509 chain/tree tests.
// The leaf carries the URI SAN spiffe://example.com/workload.
func NewThreeLevelSPIFFEChain(t *testing.T) (root, intermediate, leaf *x509.Certificate) {
	t.Helper()

	// Root CA (self-signed, RSA-2048 by default).
	rootCA := NewCertificateAuthority(t, "Root CA")
	root = rootCA.GenerateCaCertificate(t)

	// Intermediate CA: signed by rootCA, has its own ECDSA P-256 key.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate = rootCA.GenerateCaCertificate(t,
		WithPublicKey(intKey.Public()),
		WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	// Leaf: SPIFFE SVID signed by intKey; intermediate as parent so AKI = intermediate.SubjectKeyId.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf = CreateCertificate(t, tmpl, intermediate, leafKey.Public(), intKey)
	return
}
