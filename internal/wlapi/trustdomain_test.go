package wlapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTrustDomain(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)
	require.NotNil(t, trustDomain)
	assert.Equal(t, "example.com", trustDomain.Name())
}

func TestTrustDomain_RotateX509Authority(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Rotate authority
	err = trustDomain.rotateX509Authority()
	require.NoError(t, err)

	// Verify authority was created
	trustDomain.mu.RLock()
	authorities := trustDomain.x509Authorities
	trustDomain.mu.RUnlock()

	require.Len(t, authorities, 1)
	auth := authorities[0]

	// Verify certificate properties
	require.NotNil(t, auth.cert)
	assert.True(t, auth.cert.IsCA)
	assert.True(t, auth.cert.BasicConstraintsValid)

	// Verify SPIFFE ID in URIs
	require.Len(t, auth.cert.URIs, 1)
	assert.Equal(t, "spiffe://example.com", auth.cert.URIs[0].String())

	// Verify TTL (within tolerance)
	expectedNotAfter := time.Now().Add(24 * time.Hour)
	assert.WithinDuration(t, expectedNotAfter, auth.cert.NotAfter, 5*time.Second)

	// Verify key exists
	require.NotNil(t, auth.pk)
}

func TestTrustDomain_RotateJWTAuthority(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  48 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Rotate authority
	err = trustDomain.rotateJWTAuthority()
	require.NoError(t, err)

	// Verify authority was created
	trustDomain.mu.RLock()
	authorities := trustDomain.jwtAuthorities
	trustDomain.mu.RUnlock()

	require.Len(t, authorities, 1)
	auth := authorities[0]

	// Verify key ID format
	assert.Contains(t, auth.keyID, "spirl-dev-jwt-key-")

	// Verify expiration
	expectedExpiresAt := time.Now().Add(48 * time.Hour)
	assert.WithinDuration(t, expectedExpiresAt, auth.expiresAt, 5*time.Second)

	// Verify key exists
	require.NotNil(t, auth.pk)
	require.NotNil(t, auth.pk.Public())
}

func TestTrustDomain_MintX509SVID(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Setup authority
	err = trustDomain.rotateX509Authority()
	require.NoError(t, err)

	// Generate workload key
	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Mint SVID
	workloadID, err := spiffeid.FromString("spiffe://example.com/workload")
	require.NoError(t, err)

	svidCert, bundle, err := trustDomain.MintX509SVID(workloadID, workloadKey.Public(), 1*time.Hour)
	require.NoError(t, err)
	require.NotNil(t, svidCert)
	require.NotNil(t, bundle)

	// Verify SVID properties
	require.Len(t, svidCert.URIs, 1)
	assert.Equal(t, "spiffe://example.com/workload", svidCert.URIs[0].String())

	// Verify TTL
	expectedExpiry := time.Now().Add(1 * time.Hour)
	assert.WithinDuration(t, expectedExpiry, svidCert.NotAfter, 5*time.Second)

	// Verify bundle contains CA
	require.Len(t, bundle, 1)
	assert.True(t, bundle[0].IsCA)
}

func TestTrustDomain_MintX509SVID_NoAuthority(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Try to mint without rotating authority first
	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	workloadID, err := spiffeid.FromString("spiffe://example.com/workload")
	require.NoError(t, err)

	_, _, err = trustDomain.MintX509SVID(workloadID, workloadKey.Public(), 1*time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no X509 authority available")
}

func TestTrustDomain_MintJWTSVID(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Setup authority
	err = trustDomain.rotateJWTAuthority()
	require.NoError(t, err)

	// Mint JWT SVID
	workloadID, err := spiffeid.FromString("spiffe://example.com/workload")
	require.NoError(t, err)

	token, err := trustDomain.MintJWTSVID(workloadID, []string{"test-audience"}, 1*time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it looks like a JWT (three base64 segments)
	assert.Regexp(t, `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`, token)
}

func TestTrustDomain_MintJWTSVID_NoAuthority(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Try to mint without rotating authority first
	workloadID, err := spiffeid.FromString("spiffe://example.com/workload")
	require.NoError(t, err)

	_, err = trustDomain.MintJWTSVID(workloadID, []string{"test-audience"}, 1*time.Hour)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no JWT authority available")
}

func TestTrustDomain_Bundle(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Setup authorities
	err = trustDomain.rotateX509Authority()
	require.NoError(t, err)
	err = trustDomain.rotateJWTAuthority()
	require.NoError(t, err)

	// Get bundle
	bundle, err := trustDomain.Bundle()
	require.NoError(t, err)
	require.NotNil(t, bundle)

	// Verify bundle contains authorities
	assert.Equal(t, td, bundle.TrustDomain())

	// Verify X.509 authorities
	x509Authorities := bundle.X509Authorities()
	assert.Len(t, x509Authorities, 1)

	// Verify JWT authorities
	jwtAuthorities := bundle.JWTAuthorities()
	assert.Len(t, jwtAuthorities, 1)
}

func TestTrustDomain_X509Bundles(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Setup authority
	err = trustDomain.rotateX509Authority()
	require.NoError(t, err)

	// Get bundles
	bundles, err := trustDomain.X509Bundles()
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	// Verify bundle key
	bundleData, ok := bundles["spiffe://example.com"]
	require.True(t, ok)
	assert.NotEmpty(t, bundleData)
}

func TestTrustDomain_JWTBundles(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Setup authority
	err = trustDomain.rotateJWTAuthority()
	require.NoError(t, err)

	// Get bundles
	bundles, err := trustDomain.JWTBundles()
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	// Verify bundle key
	bundleData, ok := bundles["spiffe://example.com"]
	require.True(t, ok)
	assert.NotEmpty(t, bundleData)
}

func TestDERFromCertificates(t *testing.T) {
	// Create test certificates
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	err = trustDomain.rotateX509Authority()
	require.NoError(t, err)

	trustDomain.mu.RLock()
	certs := []*x509.Certificate{trustDomain.x509Authorities[0].cert}
	trustDomain.mu.RUnlock()

	// Test DER concatenation
	derBytes := DERFromCertificates(certs)
	assert.NotEmpty(t, derBytes)
	assert.Equal(t, certs[0].Raw, derBytes)
}

func Test_newSerialNumber(t *testing.T) {
	// Test serial number generation
	sn1, err := newSerialNumber()
	require.NoError(t, err)
	require.NotNil(t, sn1)

	// Verify it's greater than 0
	assert.True(t, sn1.Cmp(big.NewInt(0)) > 0)

	// Verify it's less than MaxUint128
	assert.True(t, sn1.Cmp(maxUint128) <= 0)

	// Generate multiple serial numbers to verify uniqueness
	sn2, err := newSerialNumber()
	require.NoError(t, err)
	assert.NotEqual(t, sn1, sn2, "serial numbers should be unique")
}

func Test_generateKey(t *testing.T) {
	key, err := generateKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	// Verify it's an ECDSA key
	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA key")

	// Verify it's P-256
	assert.Equal(t, elliptic.P256(), ecKey.Curve)
}

func TestTrustDomain_MultipleRotations(t *testing.T) {
	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	config := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}

	trustDomain, err := NewTrustDomain(config)
	require.NoError(t, err)

	// Rotate X.509 authority multiple times
	for i := 0; i < 3; i++ {
		err = trustDomain.rotateX509Authority()
		require.NoError(t, err)
	}

	// Verify all authorities are present
	trustDomain.mu.RLock()
	assert.Len(t, trustDomain.x509Authorities, 3)
	trustDomain.mu.RUnlock()

	// Rotate JWT authority multiple times
	for i := 0; i < 3; i++ {
		err = trustDomain.rotateJWTAuthority()
		require.NoError(t, err)
	}

	// Verify all authorities are present
	trustDomain.mu.RLock()
	assert.Len(t, trustDomain.jwtAuthorities, 3)
	trustDomain.mu.RUnlock()

	// Verify minting uses the latest authority
	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	workloadID, err := spiffeid.FromString("spiffe://example.com/workload")
	require.NoError(t, err)

	svidCert, _, err := trustDomain.MintX509SVID(workloadID, workloadKey.Public(), 1*time.Hour)
	require.NoError(t, err)

	// Verify SVID was signed by the latest authority
	trustDomain.mu.RLock()
	latestAuthority := trustDomain.x509Authorities[2]
	trustDomain.mu.RUnlock()

	// The SVID's issuer should match the latest authority's subject
	assert.Equal(t, latestAuthority.cert.Subject.String(), svidCert.Issuer.String())
}
