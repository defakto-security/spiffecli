package testx509

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewThreeLevelSPIFFEChain_ReturnsThreeCerts(t *testing.T) {
	root, intermediate, leaf := NewThreeLevelSPIFFEChain(t)

	require.NotNil(t, root)
	require.NotNil(t, intermediate)
	require.NotNil(t, leaf)
}

func TestNewThreeLevelSPIFFEChain_Subjects(t *testing.T) {
	root, intermediate, leaf := NewThreeLevelSPIFFEChain(t)

	assert.Equal(t, "Root CA", root.Subject.CommonName)
	assert.Equal(t, "Intermediate CA", intermediate.Subject.CommonName)
	assert.Equal(t, "workload", leaf.Subject.CommonName)
}

func TestNewThreeLevelSPIFFEChain_RootIsSelfSigned(t *testing.T) {
	root, _, _ := NewThreeLevelSPIFFEChain(t)

	assert.Equal(t, root.Subject.String(), root.Issuer.String())
	assert.True(t, root.IsCA)
	assert.True(t, root.BasicConstraintsValid)
}

func TestNewThreeLevelSPIFFEChain_IntermediateSignedByRoot(t *testing.T) {
	root, intermediate, _ := NewThreeLevelSPIFFEChain(t)

	assert.True(t, intermediate.IsCA)
	assert.True(t, intermediate.BasicConstraintsValid)
	assert.Equal(t, "Root CA", intermediate.Issuer.CommonName)
	assert.Equal(t, root.SubjectKeyId, intermediate.AuthorityKeyId,
		"intermediate AKI must match root SKI")
}

func TestNewThreeLevelSPIFFEChain_LeafSignedByIntermediate(t *testing.T) {
	_, intermediate, leaf := NewThreeLevelSPIFFEChain(t)

	assert.False(t, leaf.IsCA)
	assert.True(t, leaf.BasicConstraintsValid)
	assert.Equal(t, intermediate.SubjectKeyId, leaf.AuthorityKeyId,
		"leaf AKI must match intermediate SKI")
}

func TestNewThreeLevelSPIFFEChain_LeafSPIFFEURI(t *testing.T) {
	_, _, leaf := NewThreeLevelSPIFFEChain(t)

	require.Len(t, leaf.URIs, 1, "leaf must have exactly one URI SAN")
	assert.Equal(t, "spiffe://example.com/workload", leaf.URIs[0].String())
}

func TestNewThreeLevelSPIFFEChain_LeafKeyUsage(t *testing.T) {
	_, _, leaf := NewThreeLevelSPIFFEChain(t)

	assert.NotZero(t, leaf.KeyUsage&x509.KeyUsageDigitalSignature,
		"leaf must have KeyUsageDigitalSignature")
	assert.Zero(t, leaf.KeyUsage&x509.KeyUsageCertSign,
		"leaf must not have KeyUsageCertSign")
}

func TestNewThreeLevelSPIFFEChain_LeafValidityMatchesRoot(t *testing.T) {
	root, _, leaf := NewThreeLevelSPIFFEChain(t)

	assert.Equal(t, root.NotBefore, leaf.NotBefore,
		"leaf NotBefore must match root NotBefore")
	assert.Equal(t, root.NotAfter, leaf.NotAfter,
		"leaf NotAfter must match root NotAfter")
}

func TestNewThreeLevelSPIFFEChain_KeyAlgorithms(t *testing.T) {
	root, intermediate, leaf := NewThreeLevelSPIFFEChain(t)

	_, rootIsRSA := root.PublicKey.(*rsa.PublicKey)
	assert.True(t, rootIsRSA, "root must use RSA key (default)")

	_, intIsECDSA := intermediate.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, intIsECDSA, "intermediate must use ECDSA key")

	_, leafIsECDSA := leaf.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, leafIsECDSA, "leaf must use ECDSA key")
}

func TestNewThreeLevelSPIFFEChain_LeafVerifiesAgainstChain(t *testing.T) {
	root, intermediate, leaf := NewThreeLevelSPIFFEChain(t)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		// CurrentTime zero means use the cert's own validity window;
		// use root.NotBefore+1s so it's within range.
		CurrentTime: root.NotBefore.Add(1),
	}
	chains, err := leaf.Verify(opts)
	require.NoError(t, err, "leaf must verify against root via intermediate")
	require.NotEmpty(t, chains)
}

func TestNewThreeLevelSPIFFEChain_EachCallProducesDifferentCerts(t *testing.T) {
	root1, _, _ := NewThreeLevelSPIFFEChain(t)
	root2, _, _ := NewThreeLevelSPIFFEChain(t)

	// Different invocations generate fresh keys, so SubjectKeyIds differ.
	assert.NotEqual(t, root1.SubjectKeyId, root2.SubjectKeyId,
		"successive calls must produce independent certificate hierarchies")
}
