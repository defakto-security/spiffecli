package x509inspect

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertCertsToSummary_SanitizesControlChars verifies that ANSI escape sequences
// embedded in certificate-derived string fields (e.g. Subject CN) are replaced with
// the Unicode replacement character (U+FFFD) before reaching the terminal.
func TestConvertCertsToSummary_SanitizesControlChars(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Subject CN embeds an ANSI CSI escape (ESC [ 3 1 m = red foreground).
	maliciousCN := "legit\x1b[31mred\x1b[0m"
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: maliciousCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)

	// The raw ESC byte must never reach the terminal output.
	assert.NotContains(t, out, "\x1b", "ESC byte must not pass through to terminal output")
	// Control characters must be replaced with the Unicode replacement character.
	assert.Contains(t, out, "�", "control characters must be replaced with U+FFFD in summary output")
}

// TestConvertCertsToSummary_SanitizesNullBytes verifies that null bytes (U+0000) in
// certificate string fields are replaced rather than passed through.
func TestConvertCertsToSummary_SanitizesNullBytes(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cnWithNull := "CN\x00WithNull"
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cnWithNull},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)

	assert.NotContains(t, out, "\x00", "null byte must not pass through to terminal output")
}

// TestConvertCertsToSummary_PreservesNonASCIIUnicode verifies that printable non-ASCII
// characters (CJK, emoji, etc.) are preserved unchanged by any sanitization applied to
// certificate fields.
func TestConvertCertsToSummary_PreservesNonASCIIUnicode(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// CJK and emoji — both printable, neither in a control-char range.
	unicodeCN := "服务\U0001F600"
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: unicodeCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)

	assert.Contains(t, out, "服务", "CJK characters must be preserved in summary output")
	assert.Contains(t, out, "\U0001F600", "emoji must be preserved in summary output")
}

// TestConvertCertsToSummary_SanitizesC1ControlChars verifies that C1 control characters
// (U+0080 – U+009F) embedded in certificate fields are replaced with U+FFFD.
func TestConvertCertsToSummary_SanitizesC1ControlChars(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// U+0080 is the first C1 control character.
	cnWithC1 := "CN\xc2\x80WithC1" // UTF-8 encoding of U+0080
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: cnWithC1},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)

	assert.NotContains(t, out, "\u0080", "U+0080 (C1 control char) must not pass through to terminal output")
	assert.Contains(t, out, "�", "C1 control characters must be replaced with U+FFFD")
}

// TestSanitizeForTerminal verifies the helper function directly.
func TestSanitizeForTerminal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"normal ASCII", "hello world", "hello world"},
		{"ESC ANSI sequence", "legit\x1b[31mred\x1b[0m", "legit�[31mred�[0m"},
		{"null byte", "CN\x00WithNull", "CN�WithNull"},
		{"C1 control U+0080", "CN\xc2\x80end", "CN�end"},
		{"C1 control U+009F", "CN\xc2\x9fend", "CN�end"},
		{"DEL U+007F", "CN\x7fend", "CN�end"},
		{"tab U+0009 replaced", "tab\there", "tab�here"},
		{"newline U+000A replaced", "line\nbreak", "line�break"},
		{"CJK preserved", "服务", "服务"},
		{"emoji preserved", "\U0001F600", "\U0001F600"},
		{"mixed: control + printable", "a\x1b[1mb", "a�[1mb"},
		{"printable non-ASCII after control", "\x01中文", "�中文"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForTerminal(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestX509InspectOutputOptions_InColor(t *testing.T) {
	assert.False(t, X509InspectOutputOptions{Color: false}.InColor())
	assert.True(t, X509InspectOutputOptions{Color: true}.InColor())
}

// ---- certToInfo field coverage ----

func TestCertToInfo_SANFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/svc")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svc"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		DNSNames:              []string{"svc.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"svc@example.com"},
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		AuthorityKeyId:        issuer.SubjectKeyId,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Contains(t, info.DNSNames, "svc.example.com")
	assert.Contains(t, info.IPAddresses, "10.0.0.1")
	assert.Contains(t, info.EmailAddresses, "svc@example.com")
	assert.Contains(t, info.URIs, "spiffe://example.com/svc")
	assert.NotEmpty(t, info.SubjectKeyID, "SubjectKeyID should be populated")
	assert.NotEmpty(t, info.AuthorityKeyID, "AuthorityKeyID should be populated")
	assert.NotEmpty(t, info.Subject)
	assert.NotEmpty(t, info.Issuer)
	assert.NotEmpty(t, info.NotBefore)
	assert.NotEmpty(t, info.NotAfter)
	assert.NotEmpty(t, info.SignatureAlgorithm)
	assert.Empty(t, info.SpiffeIDError, "valid SPIFFE ID should leave error code empty")
}

func TestCertToInfo_SHA256FingerprintMatchesCertRaw(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	info := certToInfo(leaf)
	expected := fmt.Sprintf("%x", sha256.Sum256(leaf.Raw))
	assert.Equal(t, expected, info.SHA256Fingerprint)
}

func TestCertToInfo_NonSpiffeURIDoesNotPopulateSpiffeFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI, _ := url.Parse("https://not-spiffe.example.com/path")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID, "https URI is not a SPIFFE ID")
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Contains(t, info.URIs, "https://not-spiffe.example.com/path", "URI should still appear in URIs field")
	assert.Empty(t, info.SpiffeIDError, "non-SPIFFE URI should not surface an error code")
	assert.Empty(t, info.SpiffeIDErrorDetail, "non-SPIFFE URI should not surface an error detail")
}

// TestCertToInfo_NonSpiffeURIOnly_NoErrorFields is a regression test for the review comment
// "SpiffeIDParseError is set from the first spiffeid.FromURI error even when the URI SAN is
// simply non-SPIFFE (e.g. https://...)". Verifies that all three error fields remain empty
// when the certificate has only non-SPIFFE scheme URIs.
func TestCertToInfo_NonSpiffeURIOnly_NoErrorFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Three non-SPIFFE URIs: none should trigger any error field.
	u1, _ := url.Parse("https://service.example.com/api")
	u2, _ := url.Parse("http://internal.example.com")
	u3, _ := url.Parse("urn:example:resource")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "non-spiffe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2, u3},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID)
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Empty(t, info.SpiffeIDError, "non-SPIFFE URIs must not set the stable error code")
	assert.Empty(t, info.SpiffeIDErrorDetail, "non-SPIFFE URIs must not set the error detail")
	assert.Empty(t, info.spiffeIDLibraryError, "non-SPIFFE URIs must not set the internal library error")
}

func TestCertToInfo_NonSpiffeURIBeforeSpiffeURI_PopulatesSpiffeFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI, _ := url.Parse("https://example.com")
	spiffeURI, _ := url.Parse("spiffe://example.com/svc")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svc"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI, spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Equal(t, "spiffe://example.com/svc", info.SpiffeID)
	assert.Equal(t, "example.com", info.TrustDomain)
	assert.Equal(t, "/svc", info.Path)
	assert.Empty(t, info.SpiffeIDError, "exactly one valid SPIFFE ID found, error code should be empty")
}

func TestCertToInfo_MultipleSpiffeURIs_LeavesSpiffeFieldsEmpty(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI1, _ := url.Parse("spiffe://example.com/one")
	spiffeURI2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ambiguous"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI1, spiffeURI2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID, "ambiguous: multiple SPIFFE URIs should leave SpiffeID empty")
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Contains(t, info.URIs, "spiffe://example.com/one")
	assert.Contains(t, info.URIs, "spiffe://example.com/two")
	assert.Equal(t, SpiffeIDErrorMultipleIDs, info.SpiffeIDError)
}

func TestCertToInfo_SpiffeURIFirst_NonSpiffeAfter_PopulatesSpiffeFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/svc")
	httpsURI, _ := url.Parse("https://example.com")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svc"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI, httpsURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Equal(t, "spiffe://example.com/svc", info.SpiffeID)
	assert.Equal(t, "example.com", info.TrustDomain)
	assert.Equal(t, "/svc", info.Path)
	assert.Empty(t, info.SpiffeIDError, "exactly one valid SPIFFE ID found, error code should be empty")
}

func TestCertToInfo_MultipleNonSpiffeURIs_LeavesSpiffeFieldsEmpty(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI1, _ := url.Parse("https://example.com/one")
	httpsURI2, _ := url.Parse("https://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI1, httpsURI2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID)
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Contains(t, info.URIs, "https://example.com/one")
	assert.Contains(t, info.URIs, "https://example.com/two")
	assert.Empty(t, info.SpiffeIDError, "non-SPIFFE URIs should not surface an error code")
}

func TestCertToInfo_MalformedSpiffeURI_PopulatesParseError(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// spiffe:// with no trust domain is a well-formed URI that fails SPIFFE ID parsing.
	malformedURI, _ := url.Parse("spiffe://")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "malformed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{malformedURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID, "malformed SPIFFE URI should not populate SpiffeID")
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Equal(t, SpiffeIDErrorInvalidURI, info.SpiffeIDError, "malformed SPIFFE URI should set stable error code")
	assert.NotEmpty(t, info.SpiffeIDErrorDetail, "malformed SPIFFE URI should populate error detail")
}

func TestCertToInfo_NoURISAN_EmptyParseError(t *testing.T) {
	ca := testx509.NewCertificateAuthority(t, "Test CA")
	caCert := ca.GenerateCaCertificate(t)
	info := certToInfo(caCert)

	assert.Empty(t, info.SpiffeID)
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Empty(t, info.SpiffeIDError, "no URI SANs means no error code to report")
}

func TestCertToInfo_NonSpiffeAndMalformedSpiffeURI_PopulatesParseError(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI, _ := url.Parse("https://example.com/other")
	malformedSpiffeURI, _ := url.Parse("spiffe://")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mixed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI, malformedSpiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID)
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Equal(t, SpiffeIDErrorInvalidURI, info.SpiffeIDError, "malformed spiffe:// URI should set stable error code")
}

// TestCertToInfo_NonSpiffeSchemes_NoParseError verifies that URIs with schemes other
// than "spiffe" never surface as SpiffeIDError, regardless of scheme type.
func TestCertToInfo_NonSpiffeSchemes_NoParseError(t *testing.T) {
	schemes := []struct {
		name    string
		rawURI  string
	}{
		{"http", "http://example.com/path"},
		{"ftp", "ftp://files.example.com/data"},
		{"urn", "urn:example:resource"},
		{"custom", "myscheme://host/path"},
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range schemes {
		t.Run(tc.name, func(t *testing.T) {
			uri, _ := url.Parse(tc.rawURI)
			issuer := ca.GetIssuerTemplate(t)
			template := x509.Certificate{
				SerialNumber:          big.NewInt(99),
				Subject:               pkix.Name{CommonName: "test"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				IsCA:                  false,
				URIs:                  []*url.URL{uri},
			}
			cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
			info := certToInfo(cert)

			assert.Empty(t, info.SpiffeIDError, "non-spiffe URI scheme %q must not surface an error code", tc.name)
			assert.Empty(t, info.SpiffeID)
			assert.Contains(t, info.URIs, tc.rawURI, "URI should still appear in the URIs field")
		})
	}
}

// TestCertToInfo_ValidAndMalformedSpiffeURI_PopulatesSpiffeFields verifies that when
// a certificate contains one valid spiffe:// URI and one malformed spiffe:// URI,
// the single valid match wins: SPIFFE fields are populated and SpiffeIDError is empty.
func TestCertToInfo_ValidAndMalformedSpiffeURI_PopulatesSpiffeFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	validURI, _ := url.Parse("spiffe://example.com/svc")
	malformedURI, _ := url.Parse("spiffe://") // missing trust domain
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mixed-spiffe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{validURI, malformedURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Equal(t, "spiffe://example.com/svc", info.SpiffeID)
	assert.Equal(t, "example.com", info.TrustDomain)
	assert.Equal(t, "/svc", info.Path)
	assert.Empty(t, info.SpiffeIDError, "exactly one valid SPIFFE ID found; error code should be empty")
}

// TestCertToInfo_MalformedSpiffeBeforeValidSpiffe_PopulatesSpiffeFields verifies that
// ordering doesn't matter: a malformed spiffe:// URI before a valid one still results
// in SPIFFE fields being populated (case-1 path wins over firstParseErr).
func TestCertToInfo_MalformedSpiffeBeforeValidSpiffe_PopulatesSpiffeFields(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	malformedURI, _ := url.Parse("spiffe://") // listed first
	validURI, _ := url.Parse("spiffe://example.com/svc")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "malformed-first"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{malformedURI, validURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Equal(t, "spiffe://example.com/svc", info.SpiffeID)
	assert.Equal(t, "example.com", info.TrustDomain)
	assert.Equal(t, "/svc", info.Path)
	assert.Empty(t, info.SpiffeIDError, "one valid SPIFFE ID found; malformed-first ordering must not affect result")
}

// TestCertToInfo_NonSpiffeAndTwoValidSpiffeURIs_MultipleError verifies that non-SPIFFE
// URIs do not interfere with the "multiple SPIFFE IDs found" error when two valid
// spiffe:// URIs are present alongside a non-SPIFFE URI.
func TestCertToInfo_NonSpiffeAndTwoValidSpiffeURIs_MultipleError(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI, _ := url.Parse("https://example.com")
	spiffeURI1, _ := url.Parse("spiffe://example.com/one")
	spiffeURI2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "three-uris"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI, spiffeURI1, spiffeURI2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	assert.Empty(t, info.SpiffeID)
	assert.Empty(t, info.TrustDomain)
	assert.Empty(t, info.Path)
	assert.Equal(t, SpiffeIDErrorMultipleIDs, info.SpiffeIDError)
}

// TestCertToInfo_MultipleSpiffeURIs_ErrorDetailContainsExpectedText verifies the
// SpiffeIDErrorDetail value is the hardcoded detail string, not library-internal text.
func TestCertToInfo_MultipleSpiffeURIs_ErrorDetailContainsExpectedText(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "multi-spiffe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	require.Equal(t, SpiffeIDErrorMultipleIDs, info.SpiffeIDError)
	assert.Equal(t, "certificate contains multiple SPIFFE IDs", info.SpiffeIDErrorDetail,
		"SpiffeIDErrorDetail must use the stable hardcoded string, not a library-internal message")
}

// TestCertToInfo_MalformedSpiffeURI_ErrorDetailIsNonEmpty verifies that for INVALID_SPIFFE_URI
// the detail field is non-empty and distinct from the stable code constant.
func TestCertToInfo_MalformedSpiffeURI_ErrorDetailIsNonEmpty(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	malformedURI, _ := url.Parse("spiffe://")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bad-spiffe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{malformedURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	require.Equal(t, SpiffeIDErrorInvalidURI, info.SpiffeIDError)
	assert.Equal(t, "URI is not a valid SPIFFE ID", info.SpiffeIDErrorDetail,
		"SpiffeIDErrorDetail must be the stable fixed string, not raw library text")
	assert.NotEmpty(t, info.spiffeIDLibraryError, "spiffeIDLibraryError must hold the raw library error for internal use")
}

// TestCertToInfo_NonSpiffeAndMalformedSpiffeURI_ErrorDetailIsNonEmpty verifies that
// when a certificate has a non-SPIFFE URI plus a malformed spiffe:// URI, SpiffeIDErrorDetail
// is populated alongside the stable code.
func TestCertToInfo_NonSpiffeAndMalformedSpiffeURI_ErrorDetailIsNonEmpty(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	httpsURI, _ := url.Parse("https://example.com/other")
	malformedSpiffeURI, _ := url.Parse("spiffe://")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mixed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{httpsURI, malformedSpiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	require.Equal(t, SpiffeIDErrorInvalidURI, info.SpiffeIDError)
	assert.Equal(t, "URI is not a valid SPIFFE ID", info.SpiffeIDErrorDetail,
		"SpiffeIDErrorDetail must be the stable fixed string for mixed non-SPIFFE + malformed-SPIFFE case")
	assert.NotEmpty(t, info.spiffeIDLibraryError, "spiffeIDLibraryError must hold the raw library error for internal use")
}

// TestCertToInfo_NoSpiffeError_ErrorDetailIsEmpty verifies that SpiffeIDErrorDetail
// is empty whenever SpiffeIDError is empty (no false positives).
func TestCertToInfo_NoSpiffeError_ErrorDetailIsEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	info := certToInfo(leaf)

	assert.Empty(t, info.SpiffeIDError)
	assert.Empty(t, info.SpiffeIDErrorDetail, "detail must be empty when there is no error")
}

// TestCertToInfo_ValidSVID_LibraryErrorIsEmpty verifies that spiffeIDLibraryError
// is never populated for a conformant X.509-SVID.
func TestCertToInfo_ValidSVID_LibraryErrorIsEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	info := certToInfo(leaf)

	assert.Empty(t, info.spiffeIDLibraryError, "spiffeIDLibraryError must be empty for a valid SVID")
}

// TestCertToInfo_MultipleIDs_LibraryErrorIsEmpty verifies that spiffeIDLibraryError
// is not set for the MULTIPLE_SPIFFE_IDS case — there is no parse error, only ambiguity.
func TestCertToInfo_MultipleIDs_LibraryErrorIsEmpty(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "multi-id"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	require.Equal(t, SpiffeIDErrorMultipleIDs, info.SpiffeIDError)
	assert.Empty(t, info.spiffeIDLibraryError, "spiffeIDLibraryError must be empty for MULTIPLE_SPIFFE_IDS (no parse error)")
}

// TestCertToInfo_InvalidURI_LibraryErrorIsDistinctFromFixedString verifies that
// spiffeIDLibraryError holds the actual go-spiffe parse error, not the stable fixed string
// placed in SpiffeIDErrorDetail. The two values must differ to confirm the separation is real.
func TestCertToInfo_InvalidURI_LibraryErrorIsDistinctFromFixedString(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	malformedURI, _ := url.Parse("spiffe://")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "bad-spiffe2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{malformedURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	info := certToInfo(cert)

	require.Equal(t, SpiffeIDErrorInvalidURI, info.SpiffeIDError)
	const fixedString = "URI is not a valid SPIFFE ID"
	assert.Equal(t, fixedString, info.SpiffeIDErrorDetail)
	assert.NotEmpty(t, info.spiffeIDLibraryError, "spiffeIDLibraryError must be non-empty")
	assert.NotEqual(t, fixedString, info.spiffeIDLibraryError,
		"spiffeIDLibraryError must be the actual library error, not a copy of the fixed public string")
}

// ---- keyAlgorithmString ----

func TestKeyAlgorithmString_RSA2048(t *testing.T) {
	// NewCertificateAuthority without WithSigner defaults to RSA 2048.
	ca := testx509.NewCertificateAuthority(t, "RSA CA")
	rsaCert := ca.GenerateCaCertificate(t)
	assert.Equal(t, "RSA 2048", keyAlgorithmString(rsaCert))
}

func TestKeyAlgorithmString_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "ECDSA CA", testx509.WithSigner(key))
	cert := ca.GenerateCaCertificate(t)
	assert.Equal(t, "ECDSA P-256", keyAlgorithmString(cert))
}

func TestKeyAlgorithmString_Ed25519(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Signing CA", testx509.WithSigner(caKey))
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ed25519-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, edPub, caKey)
	assert.Equal(t, "Ed25519", keyAlgorithmString(cert))
}

func TestKeyAlgorithmString_Unknown(t *testing.T) {
	// Synthesize a certificate with a public key type that does not match any
	// known case. This exercises the default branch that previously leaked the
	// Go concrete type name via fmt.Sprintf("unknown (%T)", pub).
	type customKey struct{}
	cert := &x509.Certificate{PublicKey: customKey{}}
	result := keyAlgorithmString(cert)
	assert.Equal(t, "unknown", result)
	assert.NotContains(t, result, "customKey", "must not leak Go type names into structured output")
}

// ---- decodeKeyUsage / decodeExtKeyUsage ----

func TestDecodeKeyUsage_CombinedBits(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	names := decodeKeyUsage(usage)
	assert.Contains(t, names, "digitalSignature")
	assert.Contains(t, names, "keyCertSign")
	assert.Contains(t, names, "cRLSign")
}

func TestDecodeKeyUsage_Empty(t *testing.T) {
	names := decodeKeyUsage(0)
	assert.NotNil(t, names)
	assert.Empty(t, names)
}

func TestDecodeKeyUsage_AllBits(t *testing.T) {
	usage := x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageDecipherOnly
	names := decodeKeyUsage(usage)
	require.Len(t, names, 9)
	assert.Contains(t, names, "digitalSignature")
	assert.Contains(t, names, "contentCommitment")
	assert.Contains(t, names, "keyEncipherment")
	assert.Contains(t, names, "dataEncipherment")
	assert.Contains(t, names, "keyAgreement")
	assert.Contains(t, names, "keyCertSign")
	assert.Contains(t, names, "cRLSign")
	assert.Contains(t, names, "encipherOnly")
	assert.Contains(t, names, "decipherOnly")
}

func TestDecodeKeyUsage_Empty_JSONMarshal(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-key-usage"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := ConvertCertsToJson([]*x509.Certificate{cert}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Contains(t, out, `"key_usage":[]`, "zero key usage must marshal as [] not null")
}

func TestDecodeKeyUsage_Empty_YAMLMarshal(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-key-usage"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := ConvertCertsToYaml([]*x509.Certificate{cert}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Contains(t, out, "key_usage: []", "zero key usage must marshal as [] not null in YAML")
	assert.NotContains(t, out, "key_usage: null", "zero key usage must not marshal as null in YAML")
}

func TestDecodeExtKeyUsage_Empty(t *testing.T) {
	names := decodeExtKeyUsage(nil)
	assert.NotNil(t, names)
	assert.Empty(t, names)
}

// TestDecodeExtKeyUsage_EmptyNonNilInput mirrors TestDecodeExtKeyUsage_Empty but
// passes an empty (non-nil) slice, ensuring the result is still non-nil.
func TestDecodeExtKeyUsage_EmptyNonNilInput(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{})
	assert.NotNil(t, names)
	assert.Empty(t, names)
}

// TestDecodeExtKeyUsage_Empty_JSONOmitted verifies that when a certificate carries no
// EKUs the "extended_key_usage" field is absent from JSON output (omitempty tag).
// If omitempty were ever removed, a nil slice would produce "extended_key_usage":null
// and break consumers.
func TestDecodeExtKeyUsage_Empty_JSONOmitted(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "no-eku"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := ConvertCertsToJson([]*x509.Certificate{cert}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.NotContains(t, out, "extended_key_usage", "extended_key_usage must be absent from JSON when no EKUs (omitempty)")
}

// TestDecodeExtKeyUsage_Empty_YAMLOmitted is the YAML counterpart of
// TestDecodeExtKeyUsage_Empty_JSONOmitted.
func TestDecodeExtKeyUsage_Empty_YAMLOmitted(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(4),
		Subject:               pkix.Name{CommonName: "no-eku-yaml"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	out, err := ConvertCertsToYaml([]*x509.Certificate{cert}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.NotContains(t, out, "extended_key_usage", "extended_key_usage must be absent from YAML when no EKUs (omitempty)")
}

func TestDecodeExtKeyUsage_AllNamedValues(t *testing.T) {
	tests := []struct {
		eku  x509.ExtKeyUsage
		want string
	}{
		{x509.ExtKeyUsageAny, "any"},
		{x509.ExtKeyUsageServerAuth, "serverAuth"},
		{x509.ExtKeyUsageClientAuth, "clientAuth"},
		{x509.ExtKeyUsageCodeSigning, "codeSigning"},
		{x509.ExtKeyUsageEmailProtection, "emailProtection"},
		{x509.ExtKeyUsageIPSECEndSystem, "ipsecEndSystem"},
		{x509.ExtKeyUsageIPSECTunnel, "ipsecTunnel"},
		{x509.ExtKeyUsageIPSECUser, "ipsecUser"},
		{x509.ExtKeyUsageTimeStamping, "timeStamping"},
		{x509.ExtKeyUsageOCSPSigning, "ocspSigning"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "msServerGatedCrypto"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "nsServerGatedCrypto"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "msCommercialCodeSigning"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "msKernelCodeSigning"},
	}

	require.Len(t, tests, len(extKeyUsageNames), "test table must cover every entry in extKeyUsageNames")

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			names := decodeExtKeyUsage([]x509.ExtKeyUsage{tt.eku})
			require.Len(t, names, 1)
			assert.Equal(t, tt.want, names[0])
		})
	}
}

func TestDecodeExtKeyUsage_UnknownValue(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsage(9999)})
	require.Len(t, names, 1)
	assert.Contains(t, names[0], "unknown")
}

// TestDecodeExtKeyUsage_MultipleEKUsPreservesOrder verifies that when multiple EKUs
// are passed in a single call the results are returned in the same order as the input.
func TestDecodeExtKeyUsage_MultipleEKUsPreservesOrder(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	})
	require.Len(t, names, 3)
	assert.Equal(t, "serverAuth", names[0])
	assert.Equal(t, "clientAuth", names[1])
	assert.Equal(t, "codeSigning", names[2])
}

// TestDecodeExtKeyUsage_MixedKnownAndUnknown verifies that known and unknown EKU values
// can coexist in one call: known EKUs are resolved by name and unknowns produce the
// "unknown(N)" sentinel, both in input order.
func TestDecodeExtKeyUsage_MixedKnownAndUnknown(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsage(9999),
		x509.ExtKeyUsageClientAuth,
	})
	require.Len(t, names, 3)
	assert.Equal(t, "serverAuth", names[0])
	assert.Contains(t, names[1], "unknown")
	assert.Equal(t, "clientAuth", names[2])
}

// TestExtKeyUsageNames_MicrosoftLabels verifies the renamed Microsoft EKU labels
// are consistent with the msServerGatedCrypto convention (prefix only, no redundant
// "Microsoft" in the middle).
func TestExtKeyUsageNames_MicrosoftLabels(t *testing.T) {
	tests := []struct {
		eku  x509.ExtKeyUsage
		want string
	}{
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "msCommercialCodeSigning"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "msKernelCodeSigning"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "msServerGatedCrypto"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got, ok := extKeyUsageNames[tt.eku]
			require.True(t, ok, "EKU %v not found in extKeyUsageNames", tt.eku)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestExtKeyUsageNames_NoRedundantMicrosoftInfix verifies the old redundant label
// strings (msMicrosoftCommercialCodeSigning, msMicrosoftKernelCodeSigning) are not
// present in extKeyUsageNames after the rename.
func TestExtKeyUsageNames_NoRedundantMicrosoftInfix(t *testing.T) {
	for _, label := range extKeyUsageNames {
		assert.NotContains(t, label, "msMicrosoft",
			"label %q has redundant 'Microsoft' infix after ms prefix", label)
	}
}

// TestDecodeExtKeyUsage_MicrosoftCommercialCodeSigning verifies the end-to-end label
// returned by decodeExtKeyUsage for the Microsoft commercial code signing EKU.
func TestDecodeExtKeyUsage_MicrosoftCommercialCodeSigning(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftCommercialCodeSigning})
	require.Len(t, names, 1)
	assert.Equal(t, "msCommercialCodeSigning", names[0])
}

// TestDecodeExtKeyUsage_MicrosoftKernelCodeSigning verifies the end-to-end label
// returned by decodeExtKeyUsage for the Microsoft kernel code signing EKU.
func TestDecodeExtKeyUsage_MicrosoftKernelCodeSigning(t *testing.T) {
	names := decodeExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageMicrosoftKernelCodeSigning})
	require.Len(t, names, 1)
	assert.Equal(t, "msKernelCodeSigning", names[0])
}

// TestCertToInfo_ZeroKeyUsage_NonNil ensures that certToInfo returns a non-nil
// KeyUsage slice even when the certificate carries no key usage bits. This guards
// the JSON serialization path where a nil []string would produce "key_usage":null
// instead of "key_usage":[].
func TestCertToInfo_ZeroKeyUsage_NonNil(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "zero-key-usage"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	info := certToInfo(cert)
	assert.NotNil(t, info.KeyUsage, "KeyUsage must be non-nil even when no bits are set")
	assert.Empty(t, info.KeyUsage)
}

// ---- JSON converter ----

func TestConvertCertsToJson_Compact(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	out, err := ConvertCertsToJson([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{Indent: false}})
	require.NoError(t, err)
	assert.False(t, strings.Contains(out, "\n"), "compact JSON should have no newlines")
}

func TestConvertCertsToJson_Indented(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	out, err := ConvertCertsToJson([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{Indent: true}})
	require.NoError(t, err)
	assert.Contains(t, out, "\n  ", "indented JSON should have newlines with spaces")
}

func TestConvertCertsToJson_MultiCertArray(t *testing.T) {
	_, leaf1, _ := newCAAndLeafSVID(t, "spiffe://example.com/one")
	_, leaf2, _ := newCAAndLeafSVID(t, "spiffe://example.com/two")
	out, err := ConvertCertsToJson([]*x509.Certificate{leaf1, leaf2}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(out, "["), "JSON multi-cert output should be an array")
}

// ---- YAML converter ----

func TestConvertCertsToYaml_ContainsExpectedFields(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/yaml-test")
	out, err := ConvertCertsToYaml([]*x509.Certificate{leaf}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Contains(t, out, "spiffe_id:")
	assert.Contains(t, out, "spiffe://example.com/yaml-test")
	assert.Contains(t, out, "key_algorithm:")
	assert.Contains(t, out, "sha256_fingerprint:")
	assert.Contains(t, out, "signature_algorithm:")
}

// TestConvertCertsToYaml_OutputIsIndependentOfOptions verifies that ConvertCertsToYaml
// produces identical output regardless of which X509InspectOutputOptions fields are set.
// The options parameter is intentionally unused (declared as _) because YAML serialization
// has no option-dependent behavior.
func TestConvertCertsToYaml_OutputIsIndependentOfOptions(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/yaml-options-test")

	baseline, err := ConvertCertsToYaml([]*x509.Certificate{leaf}, X509ConvertOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, baseline)

	variants := []struct {
		name string
		opts X509ConvertOptions
	}{
		{"indent true", X509ConvertOptions{Output: X509InspectOutputOptions{Indent: true}}},
		{"color true", X509ConvertOptions{Output: X509InspectOutputOptions{Color: true}}},
		{"timezone UTC", X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: "UTC"}}},
		{"all fields set", X509ConvertOptions{Output: X509InspectOutputOptions{Indent: true, Color: true, TimeZone: "UTC"}}},
	}

	for _, tt := range variants {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ConvertCertsToYaml([]*x509.Certificate{leaf}, tt.opts)
			require.NoError(t, err)
			assert.Equal(t, baseline, out, "ConvertCertsToYaml output must not vary with X509ConvertOptions")
		})
	}
}

func TestConvertCertsToYaml_MultiCertArray(t *testing.T) {
	_, leaf1, _ := newCAAndLeafSVID(t, "spiffe://example.com/one")
	_, leaf2, _ := newCAAndLeafSVID(t, "spiffe://example.com/two")
	out, err := ConvertCertsToYaml([]*x509.Certificate{leaf1, leaf2}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Contains(t, out, "spiffe://example.com/one")
	assert.Contains(t, out, "spiffe://example.com/two")
}

func TestConvertCertsToJson_EmptySlice(t *testing.T) {
	out, err := ConvertCertsToJson([]*x509.Certificate{}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Equal(t, "[]", out)
}

func TestConvertCertsToYaml_EmptySlice(t *testing.T) {
	out, err := ConvertCertsToYaml([]*x509.Certificate{}, X509ConvertOptions{})
	require.NoError(t, err)
	assert.Equal(t, "[]\n", out)
}

// ---- Summary converter (uses internal convertCertsToSummary with fixed now) ----

func TestConvertCertsToSummary_FixedNow_NotExpired(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             base,
		NotAfter:              base.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	now := base.Add(time.Hour) // 1h in, 47h remaining
	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, now)
	require.NoError(t, err)
	assert.Contains(t, out, "Expires in", "should show expiry countdown for a live cert")
	assert.NotContains(t, out, "Expired at")
}

func TestConvertCertsToSummary_FixedNow_Expired(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	spiffeURI, _ := url.Parse("spiffe://example.com/old")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             base,
		NotAfter:              base.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	now := base.Add(48 * time.Hour) // past notAfter
	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, now)
	require.NoError(t, err)
	assert.Contains(t, out, "Expired at")
	assert.NotContains(t, out, "Expires in")
}

func TestConvertCertsToSummary_SingleCert_NoIndexHeader(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	out, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)
	assert.NotContains(t, out, "Certificate 1 of 1", "single cert should not show index header")
}

func TestConvertCertsToSummary_MultiCert_IndexHeaders(t *testing.T) {
	_, leaf1, _ := newCAAndLeafSVID(t, "spiffe://example.com/one")
	_, leaf2, _ := newCAAndLeafSVID(t, "spiffe://example.com/two")
	out, err := convertCertsToSummary([]*x509.Certificate{leaf1, leaf2}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)
	assert.Contains(t, out, "Certificate 1 of 2")
	assert.Contains(t, out, "Certificate 2 of 2")
}

func TestConvertCertsToSummary_NoSpiffeFields_ForCACert(t *testing.T) {
	// CA cert has no URI SAN — SPIFFE ID, Trust Domain, Path should not appear.
	ca := testx509.NewCertificateAuthority(t, "Test CA")
	caCert := ca.GenerateCaCertificate(t)
	out, err := convertCertsToSummary([]*x509.Certificate{caCert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)
	assert.NotContains(t, out, "SPIFFE ID")
	assert.NotContains(t, out, "Trust Domain")
}

func TestConvertCertsToSummary_InvalidTimezone(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	_, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: "Not/Real/Zone"}}, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error loading timezone")
}

func TestConvertCertsToSummary_PathTraversalTimezone(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	_, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: "../../etc/passwd"}}, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error loading timezone")
}

// TestConvertCertsToSummary_InjectionTimezonePatterns verifies that a range of
// injection-style timezone strings are rejected by timeutil.LoadTimezone and the
// error message is wrapped with "error loading timezone".
func TestConvertCertsToSummary_InjectionTimezonePatterns(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")

	tests := []struct {
		name     string
		timezone string
	}{
		{name: "dotdot path", timezone: "../../etc/passwd"},
		{name: "null byte", timezone: "UTC\x00evil"},
		{name: "semicolon", timezone: "UTC;rm -rf /"},
		{name: "dollar sign", timezone: "$(evil)"},
		{name: "pipe", timezone: "UTC|cmd"},
		{name: "backslash", timezone: "America\\Los_Angeles"},
		{name: "space", timezone: "America/New York"},
		{name: "newline", timezone: "UTC\nevil"},
		{name: "colon", timezone: "UTC:8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: tt.timezone}}, time.Now())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error loading timezone")
		})
	}
}

// TestConvertCertsToSummary_LeadingAndConsecutiveSlashTimezone verifies that the
// leading-slash and consecutive-slash guards introduced in commit e32354ca are
// enforced end-to-end through convertCertsToSummary.
func TestConvertCertsToSummary_LeadingAndConsecutiveSlashTimezone(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")

	tests := []struct {
		name     string
		timezone string
	}{
		{name: "leading slash — /etc/localtime", timezone: "/etc/localtime"},
		{name: "leading slash — /proc/self/environ", timezone: "/proc/self/environ"},
		{name: "leading slash — /etc/passwd", timezone: "/etc/passwd"},
		{name: "single slash only", timezone: "/"},
		{name: "double slash only", timezone: "//"},
		{name: "double slash — leading", timezone: "//etc/shadow"},
		{name: "consecutive slashes — mid", timezone: "America//Los_Angeles"},
		{name: "consecutive slashes — trailing", timezone: "America//"},
		{name: "triple consecutive slashes", timezone: "America///Los_Angeles"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: tt.timezone}}, time.Now())
			require.Error(t, err, "expected rejection of timezone %q", tt.timezone)
			assert.Contains(t, err.Error(), "error loading timezone")
		})
	}
}

// TestConvertCertsToSummary_ValidTimezone_NoError verifies that a well-formed
// timezone string is accepted by timeutil.LoadTimezone and produces output.
func TestConvertCertsToSummary_ValidTimezone_NoError(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")

	validZones := []string{"UTC", "America/Los_Angeles", "Etc/GMT+5"}
	for _, tz := range validZones {
		t.Run(tz, func(t *testing.T) {
			out, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: tz}}, time.Now())
			require.NoError(t, err)
			assert.NotEmpty(t, out)
		})
	}
}

// TestConvertCertsToSummary_EmptyTimezoneUsesLocal verifies that an empty
// timezone string does not trigger an error — the caller falls back to time.Local.
func TestConvertCertsToSummary_EmptyTimezoneUsesLocal(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	out, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: ""}}, time.Now())
	require.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestConvertCertsToSummary_IsCA_FalseForLeafCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	out, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)
	assert.Contains(t, out, "Is CA")
	assert.Contains(t, out, "false")
}

func TestConvertCertsToSummary_IsCA_TrueForCACert(t *testing.T) {
	ca := testx509.NewCertificateAuthority(t, "Test CA")
	caCert := ca.GenerateCaCertificate(t)
	out, err := convertCertsToSummary([]*x509.Certificate{caCert}, X509ConvertOptions{}, time.Now())
	require.NoError(t, err)
	assert.Contains(t, out, "Is CA")
	assert.Contains(t, out, "true")
}

// TestConvertCertsToSummary_SanitizesTimezoneInjectionInNotBeforeAndExpiresIn verifies
// that control characters in the local timezone name (simulating a compromised ZONEINFO
// database) are stripped from both the "Not Before" field and the "Expires in" line
// for a live (non-expired) certificate.
func TestConvertCertsToSummary_SanitizesTimezoneInjectionInNotBeforeAndExpiresIn(t *testing.T) {
	// Temporarily replace time.Local with a zone whose name contains ANSI escape
	// sequences, mimicking a compromised timezone database pointed to by ZONEINFO.
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone("UTC\x1b[31mINJECT\x1b[0m", 0)

	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")

	// Use a fixed "now" that is before NotAfter so we hit the "Expires in" branch.
	now := leaf.NotBefore.Add(time.Minute)
	out, err := convertCertsToSummary([]*x509.Certificate{leaf}, X509ConvertOptions{}, now)
	require.NoError(t, err)

	assert.NotContains(t, out, "\x1b", "ESC byte from compromised timezone name must not appear in Not Before or Expires in lines")
	assert.Contains(t, out, "Not Before", "Not Before field should still be present")
	assert.Contains(t, out, "Expires in", "Expires in line should still be present for a live cert")
}

// TestConvertCertsToSummary_SanitizesTimezoneInjectionInExpiredAt verifies that control
// characters in the local timezone name are stripped from the "Expired at" field for
// an already-expired certificate.
func TestConvertCertsToSummary_SanitizesTimezoneInjectionInExpiredAt(t *testing.T) {
	saved := time.Local
	t.Cleanup(func() { time.Local = saved })
	time.Local = time.FixedZone("UTC\x1b[31mINJECT\x1b[0m", 0)

	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _, caKey := newCAAndLeafSVID(t, "spiffe://example.com/expired")

	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	spiffeURI, _ := url.Parse("spiffe://example.com/expired")
	issuer := ca.GetIssuerTemplate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "expired-leaf"},
		NotBefore:             base,
		NotAfter:              base.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	// now is past NotAfter so we hit the "Expired at" branch.
	now := base.Add(2 * time.Hour)
	out, err := convertCertsToSummary([]*x509.Certificate{cert}, X509ConvertOptions{}, now)
	require.NoError(t, err)

	assert.NotContains(t, out, "\x1b", "ESC byte from compromised timezone name must not appear in Expired at or Not Before lines")
	assert.Contains(t, out, "Expired at", "Expired at field should be present for an expired cert")
	assert.NotContains(t, out, "Expires in", "Expires in should not appear for an expired cert")
}
