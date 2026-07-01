package x509verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/defakto-security/spiffecli/internal/x509util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRootAndBundle(t *testing.T) (*testx509.CertificateAuthority, string) {
	root := testx509.NewCertificateAuthority(t, "Temporary Root CA")
	rootCert := root.GenerateCaCertificate(t)
	bundlePem := pemutil.EncodeCertificate(rootCert)
	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, bundlePem, 0600))

	return root, bundlePath
}

// Test cases
func TestVerifyPemCertificateAgainstPemBundle(t *testing.T) {

	root, bundleFile := setupRootAndBundle(t)

	// create the chain
	intCa := testx509.NewCertificateAuthority(t, "Temporary Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	// verify the chain
	client := Verifier{Certificate: chainFile, CaBundle: bundleFile, CaFormat: "pem"}
	path, err := client.VerifyCertificate()
	assert.NoError(t, err)
	assert.Empty(t, path)
}

func TestVerifyUntrustedPemCertificate(t *testing.T) {
	_, bundleFile := setupRootAndBundle(t)

	// create an untrusted root
	untrustedRootCa := testx509.NewCertificateAuthority(t, "Untrusted Root CA")
	// sign the intermediate with the untrusted root

	intCa := testx509.NewCertificateAuthority(t, "Temporary Intermediate CA")
	intCert := untrustedRootCa.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	// verify the chain
	client := Verifier{Certificate: chainFile, CaBundle: bundleFile, CaFormat: "pem"}
	path, err := client.VerifyCertificate()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "certificate signed by unknown authority")
	assert.Empty(t, path)
}

func TestVerifyExpiredLeafCertificate(t *testing.T) {
	root, bundleFile := setupRootAndBundle(t)

	// create the chain
	intCa := testx509.NewCertificateAuthority(t, "Temporary Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))

	notBefore := time.Now()
	expiredPeriod := testx509.ValidityPeriod{
		NotBefore: notBefore.AddDate(0, 0, -8),
		NotAfter:  notBefore.AddDate(0, 0, -1),
	}
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}), testx509.WithValidityPeriod(expiredPeriod))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	// verify the chain
	client := Verifier{Certificate: chainFile, CaBundle: bundleFile, CaFormat: "pem"}
	path, err := client.VerifyCertificate()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "certificate has expired")
	assert.Empty(t, path)
}

// Separately test the chain retrieval logic in the Verifier
func TestChainRetrievalFromUnsupportedSchemas(t *testing.T) {
	verifier := Verifier{Certificate: "http://example.com/"}
	_, _, err := verifier.GetCertificateChain()
	assert.Error(t, err)

	verifier = Verifier{Certificate: "ftp://example.com/"}
	_, _, err = verifier.GetCertificateChain()
	assert.Error(t, err)
}

func TestChainRetrievalFromFile(t *testing.T) {
	chainCerts, expectedIntermediates := createCertificateChain(t, nil)
	chainFile := writeChainAsPem(t, chainCerts)
	verifier := Verifier{Certificate: chainFile}
	leaf, actualIntermediates, err := verifier.GetCertificateChain()
	assert.NoError(t, err)
	assert.True(t, expectedIntermediates.Equal(actualIntermediates))
	assert.Equal(t, chainCerts[0], leaf)
}

func TestChainRetrievalFromEmptyFile(t *testing.T) {
	chainFile, err := os.CreateTemp(t.TempDir(), "chain.pem")
	require.NoError(t, err)

	verifier := Verifier{Certificate: chainFile.Name()}
	_, _, err = verifier.GetCertificateChain()
	assert.Error(t, err)
}

func TestChainRetrievalFromDerFile(t *testing.T) {
	chainCerts, expectedIntermediates := createCertificateChain(t, nil)
	chainFile := writeChainAsDer(t, chainCerts)
	verifier := Verifier{Certificate: chainFile, Format: "der"}
	leaf, actualIntermediates, err := verifier.GetCertificateChain()
	assert.NoError(t, err)
	assert.True(t, expectedIntermediates.Equal(actualIntermediates))
	assert.Equal(t, chainCerts[0], leaf)
}

func TestChainRetrievalWithIncorrectFormat(t *testing.T) {
	chainCerts, _ := createCertificateChain(t, nil)
	chainFile := writeChainAsDer(t, chainCerts)
	verifier := Verifier{Certificate: chainFile, Format: "pem"}
	_, _, err := verifier.GetCertificateChain()
	assert.Error(t, err)
}

func TestChainRetrievalWithPassword(t *testing.T) {
	verifier := Verifier{Certificate: "testdata/encrypted_chain.p12", Password: "password123", Format: "der"}
	_, _, err := verifier.GetCertificateChain()
	assert.NoError(t, err)
}

// This sets up a fake server and client and performs a full test of the Verifier.
// It tests GetCertificateChain() in passing.
func TestHTTPServerChain(t *testing.T) {
	rootCert, ts, client := createTestServerAndClient(t)
	defer ts.Close()

	encodedRoot := pemutil.EncodeCertificate(rootCert)

	// Write the CA bundle to a file
	caBundlePath := writeTempFile(t, "ca-bundle.pem", encodedRoot)

	verifier := Verifier{CaBundle: caBundlePath, CaFormat: "pem", Certificate: ts.URL, HttpClient: client}
	// verify the chain
	path, err := verifier.VerifyCertificate()
	assert.NoError(t, err)
	assert.Empty(t, path)

}

func writeChainAsDer(t *testing.T, chain []*x509.Certificate) string {
	chainFile, err := os.CreateTemp(t.TempDir(), "chain.der")
	require.NoError(t, err)
	defer func() { _ = chainFile.Close() }()

	for _, cert := range chain {
		derBytes := cert.Raw
		_, err = chainFile.Write(derBytes)
		require.NoError(t, err)
	}

	return chainFile.Name()
}

// helper functions
func writeTempFile(t *testing.T, name string, data []byte) string {
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func writeChainAsPem(t *testing.T, chain []*x509.Certificate) string {
	return writeTempFile(t, "chain.pem", pemutil.EncodeCertificates(chain))
}

func convertTLSCertToX509Chain(t *testing.T, tlsCert *tls.Certificate) []*x509.Certificate {
	var chain []*x509.Certificate

	for _, certBytes := range tlsCert.Certificate {
		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)
		chain = append(chain, cert)
	}

	return chain
}

// verifier.GetCertificateChain() returns a certificate and a CertPool. We
// can only check for equality for the CertPool.
// We need to write the chain to a temporary file.
func createCertificateChain(t *testing.T, leafPair crypto.Signer) ([]*x509.Certificate, *x509.CertPool) {
	_, chain := createRootAndChainForServer(t, "www.example.com", leafPair)
	chainCerts := convertTLSCertToX509Chain(t, &chain)
	expectedIntermediates := x509.NewCertPool()
	expectedIntermediates.AddCert(chainCerts[1]) // The intermediate is always the second one in this case

	return chainCerts, expectedIntermediates
}

func createRootAndChain(t *testing.T, serverName string, leafPair crypto.Signer) (*x509.Certificate, []*x509.Certificate) {
	validityStart := time.Now()

	// We need to create keys for the intermediate and leaf certificate
	rootValidity := testx509.ValidityPeriod{
		NotBefore: validityStart.AddDate(-1, 1, 0),
		NotAfter:  time.Now().AddDate(10, 0, 0),
	}
	rootCa := testx509.NewCertificateAuthority(t, "Root CA")
	rootCert := rootCa.GenerateCaCertificate(t, testx509.WithValidityPeriod(rootValidity))

	intValidity := testx509.ValidityPeriod{
		NotBefore: validityStart.AddDate(-1, 0, 0),
		NotAfter:  time.Now().AddDate(7, 0, 0),
	}
	intCa := testx509.NewCertificateAuthority(t, "Intermediate CA")
	intCert := rootCa.GenerateCaCertificate(t, testx509.WithValidityPeriod(intValidity), testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))

	if leafPair == nil {
		var err error
		leafPair, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "could not generate random public key for leaf: %w", err)
	}
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: serverName}), testx509.WithPublicKey(leafPair.Public()))

	chain := []*x509.Certificate{leafCert, intCert}
	return rootCert, chain
}

func createRootAndChainForServer(t *testing.T, serverName string, leafPair crypto.Signer) (*x509.Certificate, tls.Certificate) {
	rootCert, x509Chain := createRootAndChain(t, serverName, leafPair)
	tlsChain := tls.Certificate{
		PrivateKey: leafPair,
		Leaf:       x509Chain[0],
	}
	for _, cert := range x509Chain {
		tlsChain.Certificate = append(tlsChain.Certificate, cert.Raw)
	}
	return rootCert, tlsChain
}

func createTestServerAndClient(t *testing.T) (*x509.Certificate, *httptest.Server, x509util.HTTPClient) {
	serverName := "www.example.com"
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootCert, chain := createRootAndChainForServer(t, serverName, keyPair)

	certPool := x509.NewCertPool()
	certPool.AddCert(rootCert)

	ts := createTestServer(serverName, chain, certPool)

	client := &x509util.RealHTTPClient{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // test configuration
					RootCAs:            certPool,
				},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("tcp", ts.Listener.Addr().String())
				},
			},
		},
	}

	return rootCert, ts, client
}

func createTestServer(serverName string, chain tls.Certificate, rootCas *x509.CertPool) *httptest.Server {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, TLS!"))
	}))
	ts.TLS = &tls.Config{
		RootCAs:    rootCas,
		ServerName: serverName,
	}
	ts.TLS.Certificates = append(ts.TLS.Certificates, chain)
	ts.StartTLS()

	return ts
}
