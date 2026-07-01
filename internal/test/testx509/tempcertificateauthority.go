package testx509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 required by RFC 5280 for SubjectKeyId
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

// A Test X509Authority represents a single X.509 certificate authority
// identified by a unique public key. It can either be a root (self-signed)
// authority, or an intermediate authority. It's used to test the parser on
// different sorts of certificates.
type CertificateAuthority struct {
	commonName string
	subject    pkix.Name
	privateKey crypto.Signer
}

type TempX509AuthorityOption = func(*CertificateAuthority) error

func WithSigner(signer crypto.Signer) TempX509AuthorityOption {
	return func(ca *CertificateAuthority) error {
		ca.privateKey = signer
		return nil
	}
}

func NewCertificateAuthority(t *testing.T, caName string, opts ...TempX509AuthorityOption) *CertificateAuthority {
	ca := &CertificateAuthority{
		commonName: caName,
		subject:    pkix.Name{CommonName: caName},
	}
	for _, opt := range opts {
		require.NoError(t, opt(ca))
	}
	if ca.privateKey == nil {
		signer, err := rsa.GenerateKey(rand.Reader, 2048) // Create RSA-2048 by default
		require.NoError(t, err, "could not create CA")

		ca.privateKey = signer
	}
	return ca
}

func (ca *CertificateAuthority) Public() crypto.PublicKey {
	return ca.privateKey.Public()
}

func (ca *CertificateAuthority) Subject() pkix.Name {
	return ca.subject
}

type ValidityPeriod struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type CertificateOptions struct {
	validity     ValidityPeriod
	maxPathLen   int
	serialNumber *big.Int
	publicKey    crypto.PublicKey
	subject      pkix.Name
}

type CertificateOption func(*CertificateOptions)

func WithValidityPeriod(validity ValidityPeriod) CertificateOption {
	return func(cao *CertificateOptions) {
		cao.validity = validity
	}
}

func WithMaxPathLen(maxpathlen int) CertificateOption {
	return func(cao *CertificateOptions) {
		cao.maxPathLen = maxpathlen
	}
}

func WithSerialNumber(serialNumber big.Int) CertificateOption {
	return func(cao *CertificateOptions) {
		cao.serialNumber = &serialNumber
	}
}

func WithPublicKey(publicKey crypto.PublicKey) CertificateOption {
	return func(cao *CertificateOptions) {
		cao.publicKey = publicKey
	}
}

func WithSubject(subject pkix.Name) CertificateOption {
	return func(cao *CertificateOptions) {
		cao.subject = subject
	}
}

// Generates a CA certificate signed by the certificate authority. This can be a
// self-signed (root) certificate, or an intermediate certificate.
func (ca *CertificateAuthority) GenerateCaCertificate(t *testing.T, opts ...CertificateOption) *x509.Certificate {

	// defaults
	notBefore := time.Now()
	certOptions := &CertificateOptions{
		validity: ValidityPeriod{
			NotBefore: notBefore,
			NotAfter:  notBefore.AddDate(10, 0, 0), // valid for ten years from now
		},
		maxPathLen:   -1, // default is that it's not set
		serialNumber: big.NewInt(1),
		publicKey:    ca.Public(), // default is a self-signed certificate
		subject:      ca.Subject(),
	}

	// override defaults
	for _, opt := range opts {
		opt(certOptions)
	}

	// The AuthorityKeyId will be taken from the SubjectKeyId of parent, if any,
	// unless the resulting certificate is self-signed. Otherwise the value from
	// template will be used.

	template := x509.Certificate{
		SerialNumber:          certOptions.serialNumber,
		Subject:               certOptions.subject,
		NotBefore:             certOptions.validity.NotBefore,
		NotAfter:              certOptions.validity.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            certOptions.maxPathLen,
	}

	var issuer x509.Certificate

	// If the public keys are equal, then we want a self-signed certificate.
	// Explicitly set SubjectKeyId so Go does not auto-compute it (computation
	// changed in Go 1.26), ensuring consistency with GetIssuerTemplate.
	if ca.privateKey.Public() == certOptions.publicKey {
		template.SubjectKeyId = ca.CalculateSubjectKeyId(t)
		issuer = template
	} else { // Generate the subject key id
		issuer = ca.GetIssuerTemplate(t)
	}

	return CreateCertificate(t, &template, &issuer, certOptions.publicKey, ca.privateKey)
}

// Generic leaf certificate-generation method. By default it will create a certificate valid for TLS/SSL.
func (ca *CertificateAuthority) GenerateLeafCertificate(t *testing.T, opts ...CertificateOption) *x509.Certificate {

	// defaults
	notBefore := time.Now()
	certOptions := &CertificateOptions{
		validity: ValidityPeriod{
			NotBefore: notBefore,
			NotAfter:  notBefore.AddDate(0, 0, 7), // valid for a week by default
		},
		maxPathLen:   -1,  // Default is not set
		serialNumber: nil, // Default is not set
		publicKey:    nil, // Default no key, we'll fix later
		subject:      pkix.Name{CommonName: ca.commonName},
	}

	// override defaults
	for _, opt := range opts {
		opt(certOptions)
	}

	if certOptions.serialNumber == nil {
		certOptions.serialNumber = generateSerialNumber(t)
	}

	if certOptions.publicKey == nil {
		signer, err := rsa.GenerateKey(rand.Reader, 2048) // Create RSA-2048 by default
		require.NoError(t, err, "could not generate random public key")
		certOptions.publicKey = signer.Public()

	}

	// These certificates are never self-signed.
	issuer := ca.GetIssuerTemplate(t)

	template := x509.Certificate{
		SerialNumber:   certOptions.serialNumber,
		Subject:        certOptions.subject,
		NotBefore:      certOptions.validity.NotBefore,
		NotAfter:       certOptions.validity.NotAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:           false,
		AuthorityKeyId: issuer.SubjectKeyId,
	}

	return CreateCertificate(t, &template, &issuer, certOptions.publicKey, ca.privateKey)
}

func (ca *CertificateAuthority) GetIssuerTemplate(t *testing.T) x509.Certificate {
	subjectKeyId := ca.CalculateSubjectKeyId(t)

	// Generate the subject key id
	issuer := x509.Certificate{
		Subject:      ca.Subject(),
		IsCA:         true,
		SubjectKeyId: subjectKeyId,
	}

	return issuer
}

func (ca *CertificateAuthority) CalculateSubjectKeyId(t *testing.T) []byte {
	// Marshal the public key into DER-encoded PKIX format
	pkixPublic, err := x509.MarshalPKIXPublicKey(ca.privateKey.Public())
	require.NoError(t, err, "could not marshal public key to PKIX structure")

	// Parse the public key as a SubjectPublicKeyInfo structure
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(pkixPublic, &spki)
	require.NoError(t, err, "could not unmarshal into SubjectPublicKeyInfo structure")

	// The SubjectKeyId is the SHA-1 hash of the SubjectPublicKey
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes) //nolint:gosec // SHA-1 required by RFC 5280 for SubjectKeyId
	return skid[:]
}

// This generates a random serial number for use in certificates. Using
// crypto/rand to simplify our dependencies.
func generateSerialNumber(t *testing.T) *big.Int {

	// According to the CA/B Forum TLS Baseline Requirements 2.0.7, the serial
	// number should be a non-sequential number between 0 and 2^159, and should
	// contain at least 64 bits from a CSPRNG. We'll settle on 128 bits.
	max := new(big.Int).Lsh(big.NewInt(1), uint(128))

	serial, err := rand.Int(rand.Reader, max)
	require.NoError(t, err, "could not generate random big.Int: %w", err)

	return serial
}

// NewConformantSVID generates a CA cert and a SPIFFE-conformant X.509-SVID leaf cert.
// The leaf has exactly one URI SAN (spiffeID), KeyUsage=digitalSignature,
// BasicConstraintsValid=true, and IsCA=false — all requirements of the SPIFFE X.509-SVID spec.
// Use opts (e.g. WithValidityPeriod, WithSerialNumber) to customize the leaf cert.
// Returns (caCert, leafCert, caKey).
func NewConformantSVID(t *testing.T, spiffeID string, opts ...CertificateOption) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ca := NewCertificateAuthority(t, "Test CA", WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sid, err := spiffeid.FromString(spiffeID)
	require.NoError(t, err)

	notBefore := time.Now().Add(-time.Hour)
	certOptions := &CertificateOptions{
		validity: ValidityPeriod{
			NotBefore: notBefore,
			NotAfter:  notBefore.Add(24 * time.Hour),
		},
		serialNumber: big.NewInt(42),
		subject:      pkix.Name{CommonName: "test-workload"},
	}
	for _, opt := range opts {
		opt(certOptions)
	}

	pubKey := crypto.PublicKey(leafKey.Public())
	if certOptions.publicKey != nil {
		pubKey = certOptions.publicKey
	}

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          certOptions.serialNumber,
		Subject:               certOptions.subject,
		NotBefore:             certOptions.validity.NotBefore,
		NotAfter:              certOptions.validity.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{sid.URL()},
		AuthorityKeyId:        issuer.SubjectKeyId,
	}

	leafCert := CreateCertificate(t, &template, &issuer, pubKey, caKey)
	return caCert, leafCert, caKey
}

// Wraps the standard CreateCertificate method and returns an X509.Certificate object
func CreateCertificate(t *testing.T, template *x509.Certificate, parent *x509.Certificate, pub any, priv any) *x509.Certificate {
	derBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	require.NoError(t, err, "could not create temporary DER-formatted certificate: %w", err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err, "could not parse temporary DER-formatted certificate: %w", err)

	return cert
}
