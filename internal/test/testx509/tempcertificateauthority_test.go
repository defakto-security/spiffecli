package testx509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func AssertRoot(assert *assert.Assertions, cert *x509.Certificate) {
	assert.Equal(cert.Subject, cert.Issuer)
	assert.True(cert.IsCA)
	assert.True(cert.BasicConstraintsValid)
}

func AssertValid(assert *assert.Assertions, cert *x509.Certificate) {
	now := time.Now()

	assert.True(cert.NotAfter.After(now))
	assert.True(cert.NotBefore.Before(now))
}

func AssertBitSet(assert *assert.Assertions, bitfield int, bitPos int) {
	assert.True((bitfield & (1 << bitPos)) != 0)

}

func AssertTLS(assert *assert.Assertions, cert *x509.Certificate) {
	AssertBitSet(assert, int(cert.KeyUsage), int(x509.KeyUsageDigitalSignature))
	AssertBitSet(assert, int(cert.KeyUsage), int(x509.KeyUsageKeyEncipherment))
	assert.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

// Let's just create a root CA
func TestCreateDefaultRootCA(t *testing.T) {
	assert := assert.New(t)

	ca := NewCertificateAuthority(t, "Happy Path CA")
	cert := ca.GenerateCaCertificate(t)

	assert.Equal(cert.Subject.CommonName, "Happy Path CA")
	assert.Equal(cert.Issuer.CommonName, "Happy Path CA")
	assert.NotEmpty(cert.SubjectKeyId)
	assert.Equal("RSA", cert.PublicKeyAlgorithm.String())
	assert.False(cert.MaxPathLenZero)

	AssertValid(assert, cert)
	AssertRoot(assert, cert)
}

func TestCreateRootCaWithSigner(t *testing.T) {
	assert := assert.New(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(err)
	ca := NewCertificateAuthority(t, "Happy Path CA", WithSigner(privateKey))

	cert := ca.GenerateCaCertificate(t)

	assert.Equal(cert.Subject.CommonName, "Happy Path CA")
	assert.Equal(cert.Issuer.CommonName, "Happy Path CA")

	assert.Equal("ECDSA", cert.PublicKeyAlgorithm.String())
	assert.False(cert.MaxPathLenZero)

	AssertValid(assert, cert)
	AssertRoot(assert, cert)
}

func TestCreateExpired(t *testing.T) {
	assert := assert.New(t)

	ca := NewCertificateAuthority(t, "Expired CA")

	expiredPeriod := ValidityPeriod{
		NotBefore: time.Now().AddDate(-10, 0, 0),
		NotAfter:  time.Now().AddDate(-5, 0, 0),
	}
	cert := ca.GenerateCaCertificate(t, WithValidityPeriod(expiredPeriod))

	AssertRoot(assert, cert)
	now := time.Now()
	assert.True(cert.NotBefore.Before(now))
	assert.True(cert.NotAfter.Before(now))
}

func TestCreateFuture(t *testing.T) {
	assert := assert.New(t)

	ca := NewCertificateAuthority(t, "Expired CA")

	futureValidity := ValidityPeriod{
		NotBefore: time.Now().AddDate(5, 0, 0),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	cert := ca.GenerateCaCertificate(t, WithValidityPeriod(futureValidity))
	AssertRoot(assert, cert)
	now := time.Now()
	assert.True(cert.NotBefore.After(now))
	assert.True(cert.NotAfter.After(now))
}

func TestCreateBadValidity(t *testing.T) {
	assert := assert.New(t)

	ca := NewCertificateAuthority(t, "Expired CA")

	notBefore := time.Now()
	expiredPeriod := ValidityPeriod{
		NotBefore: notBefore.AddDate(10, 0, 0),
		NotAfter:  notBefore.AddDate(5, 0, 0),
	}
	cert := ca.GenerateCaCertificate(t, WithValidityPeriod(expiredPeriod))
	AssertRoot(assert, cert)
	now := time.Now()
	assert.True(cert.NotBefore.After(now))
	assert.True(cert.NotAfter.After(now))
	assert.True(cert.NotBefore.After(cert.NotAfter))
}

func TestCreateIntermediateCA(t *testing.T) {
	assert := assert.New(t)

	rootCa := NewCertificateAuthority(t, "Root CA")
	intCa := NewCertificateAuthority(t, "Intermediate CA")
	intCert := rootCa.GenerateCaCertificate(t, WithPublicKey(intCa.Public()), WithSubject(intCa.Subject()))
	assert.Equal(intCert.Subject.CommonName, "Intermediate CA")
	assert.Equal(intCert.Issuer.CommonName, "Root CA")
	assert.True(intCert.IsCA)
	assert.True(intCert.BasicConstraintsValid)

	rootCert := rootCa.GenerateCaCertificate(t)
	assert.Equal(rootCert.SubjectKeyId, intCert.AuthorityKeyId)
}

type LeafCertsTestSuite struct {
	suite.Suite
	RootCa *CertificateAuthority
	IntCa  *CertificateAuthority

	RootCaCert *x509.Certificate
	IntCaCert  *x509.Certificate
}

func (suite *LeafCertsTestSuite) SetupTest() {
	suite.RootCa = NewCertificateAuthority(suite.T(), "Root CA")
	suite.RootCaCert = suite.RootCa.GenerateCaCertificate(suite.T())
	suite.IntCa = NewCertificateAuthority(suite.T(), "Intermediate CA")
	notBefore := time.Now()
	intValidity := ValidityPeriod{
		NotBefore: notBefore,
		NotAfter:  notBefore.AddDate(5, 0, 0),
	}
	suite.IntCaCert = suite.RootCa.GenerateCaCertificate(suite.T(), WithPublicKey(suite.IntCa.Public()),
		WithSubject(suite.IntCa.Subject()),
		WithValidityPeriod(intValidity),
	)
}

func (suite *LeafCertsTestSuite) TestHappyPath() {
	assert := assert.New(suite.T())
	leafCert := suite.IntCa.GenerateLeafCertificate(suite.T(), WithSubject(pkix.Name{CommonName: "example.com"}))
	AssertValid(assert, leafCert)
	assert.False(leafCert.IsCA)
	assert.Greater(suite.IntCaCert.NotAfter, leafCert.NotAfter)
}

func (suite *LeafCertsTestSuite) TestExpired() {
	assert := assert.New(suite.T())

	expiredPeriod := ValidityPeriod{
		NotBefore: time.Now().AddDate(0, 0, -8),
		NotAfter:  time.Now().AddDate(0, 0, -1),
	}
	leafCert := suite.IntCa.GenerateLeafCertificate(suite.T(), WithSubject(pkix.Name{CommonName: "expired.example.com"}), WithValidityPeriod(expiredPeriod))
	now := time.Now()
	assert.True(leafCert.NotBefore.Before(now))
	assert.True(leafCert.NotAfter.Before(now))
}

func TestLeafTestSuite(t *testing.T) {
	suite.Run(t, new(LeafCertsTestSuite))
}

func TestNewConformantSVID_HappyPath(t *testing.T) {
	caCert, leafCert, caKey := NewConformantSVID(t, "spiffe://example.com/workload")

	require.NotNil(t, caCert)
	require.NotNil(t, leafCert)
	require.NotNil(t, caKey)

	// CA cert must be a CA.
	assert.True(t, caCert.IsCA)
	assert.True(t, caCert.BasicConstraintsValid)

	// Leaf must be SPIFFE-conformant.
	assert.False(t, leafCert.IsCA)
	assert.True(t, leafCert.BasicConstraintsValid)
	require.Len(t, leafCert.URIs, 1)
	assert.Equal(t, "spiffe://example.com/workload", leafCert.URIs[0].String())
	assert.NotZero(t, leafCert.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.Zero(t, leafCert.KeyUsage&x509.KeyUsageCertSign)
	assert.Zero(t, leafCert.KeyUsage&x509.KeyUsageCRLSign)
	assert.True(t, leafCert.NotBefore.Before(leafCert.NotAfter))
}

func TestNewConformantSVID_WithValidityPeriod(t *testing.T) {
	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	_, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/svc",
		WithValidityPeriod(ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
	)

	assert.Equal(t, notBefore, leafCert.NotBefore)
	assert.Equal(t, notAfter, leafCert.NotAfter)
}

func TestNewConformantSVID_WithSerialNumber(t *testing.T) {
	serial := big.NewInt(999)

	_, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/svc",
		WithSerialNumber(*serial),
	)

	assert.Equal(t, 0, leafCert.SerialNumber.Cmp(serial))
}

func TestNewConformantSVID_ExtKeyUsageConformant(t *testing.T) {
	_, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/workload")

	for _, eku := range leafCert.ExtKeyUsage {
		assert.True(t,
			eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageClientAuth,
			"ExtKeyUsage must only contain serverAuth or clientAuth; got %v", eku,
		)
	}
}

func TestNewConformantSVID_AuthorityKeyIDMatchesCA(t *testing.T) {
	caCert, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/workload")

	require.NotEmpty(t, leafCert.AuthorityKeyId)
	assert.Equal(t, caCert.SubjectKeyId, leafCert.AuthorityKeyId,
		"leaf AuthorityKeyId must match CA SubjectKeyId")
}

func TestNewConformantSVID_LeafVerifiesAgainstCA(t *testing.T) {
	caCert, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/workload")

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	_, err := leafCert.Verify(opts)
	require.NoError(t, err, "leaf cert must verify against the returned CA cert")
}

func TestNewConformantSVID_SpiffeIDWithPath(t *testing.T) {
	_, leafCert, _ := NewConformantSVID(t, "spiffe://trust-domain.example/ns/default/sa/my-service")

	require.Len(t, leafCert.URIs, 1)
	assert.Equal(t, "spiffe://trust-domain.example/ns/default/sa/my-service", leafCert.URIs[0].String())
}

func TestNewConformantSVID_WithPublicKey(t *testing.T) {
	customKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, leafCert, _ := NewConformantSVID(t, "spiffe://example.com/workload",
		WithPublicKey(customKey.Public()),
	)

	// The leaf cert should embed the custom public key.
	leafPub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "leaf public key must be ECDSA")
	assert.True(t, leafPub.Equal(customKey.Public()),
		"leaf cert must use the public key supplied via WithPublicKey")
}

// TestNewConformantSVID_SpiffeIDRoundTrip verifies that the URI SAN embedded in
// the leaf cert by NewConformantSVID round-trips cleanly through spiffeid.FromURI:
// the parsed ID must carry the original trust domain and path exactly.
// This is the regression guard for the spiffeid.FromString migration: url.Parse
// accepted any URI silently; spiffeid.FromString validates scheme, trust domain,
// and path per the SPIFFE spec.
func TestNewConformantSVID_SpiffeIDRoundTrip(t *testing.T) {
	tests := []struct {
		name         string
		spiffeID     string
		wantTD       string
		wantPath     string
	}{
		{
			name:     "simple workload",
			spiffeID: "spiffe://example.com/workload",
			wantTD:   "example.com",
			wantPath: "/workload",
		},
		{
			name:     "multi-segment path",
			spiffeID: "spiffe://trust-domain.example/ns/default/sa/my-service",
			wantTD:   "trust-domain.example",
			wantPath: "/ns/default/sa/my-service",
		},
		{
			name:     "subdomain trust domain",
			spiffeID: "spiffe://sub.example.org/svc",
			wantTD:   "sub.example.org",
			wantPath: "/svc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, leafCert, _ := NewConformantSVID(t, tt.spiffeID)

			require.Len(t, leafCert.URIs, 1, "leaf cert must have exactly one URI SAN")

			// URI scheme must always be spiffe://
			assert.Equal(t, "spiffe", leafCert.URIs[0].Scheme)

			// Round-trip: cert URI SAN must parse back as a valid SPIFFE ID.
			parsed, err := spiffeid.FromURI(leafCert.URIs[0])
			require.NoError(t, err, "cert URI SAN must be a valid SPIFFE ID")

			assert.Equal(t, tt.wantTD, parsed.TrustDomain().String(),
				"trust domain mismatch after round-trip")
			assert.Equal(t, tt.wantPath, parsed.Path(),
				"path mismatch after round-trip")

			// The string representation of the parsed ID must equal the input.
			assert.Equal(t, tt.spiffeID, parsed.String(),
				"SPIFFE ID string must survive the cert round-trip unchanged")
		})
	}
}

// TestNewConformantSVID_SpiffeIDValidation documents the boundary between inputs
// that spiffeid.FromString accepts and those it rejects. NewConformantSVID relies
// on spiffeid.FromString (rather than url.Parse) so each case below that returns
// an error would cause NewConformantSVID to call t.FailNow().
func TestNewConformantSVID_SpiffeIDValidation(t *testing.T) {
	valid := []string{
		"spiffe://example.com/workload",
		"spiffe://trust-domain.example/ns/default/sa/svc",
		"spiffe://sub.host.example/path",
	}
	for _, id := range valid {
		_, err := spiffeid.FromString(id)
		assert.NoError(t, err, "expected %q to be a valid SPIFFE ID", id)
	}

	// These inputs were silently accepted by url.Parse but must be rejected by
	// spiffeid.FromString, ensuring NewConformantSVID fails fast on bad input.
	invalid := []string{
		"https://example.com/workload",  // wrong scheme
		"http://example.com/workload",   // wrong scheme
		"",                              // empty string
		"spiffe://",                     // missing trust domain
		"not-a-uri",                     // not a URI at all
	}
	for _, id := range invalid {
		_, err := spiffeid.FromString(id)
		assert.Error(t, err, "expected %q to be rejected by spiffeid.FromString", id)
	}
}
