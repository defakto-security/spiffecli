package x509util

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readFile(t *testing.T, filePath string) []byte {
	data, err := os.ReadFile(filePath) //nolint:gosec // test file path
	require.NoError(t, err)
	return data
}

func TestIsPem(t *testing.T) {
	isPem := IsPem(readFile(t, "testdata/cert.pem"))
	assert.True(t, isPem)

	isPem = IsPem(readFile(t, "testdata/mozilla-2024-10-01.pem"))
	assert.True(t, isPem)

	isPem = IsPem(readFile(t, "testdata/cert.der"))
	assert.False(t, isPem)
}

func TestReadBundles(t *testing.T) {
	certPool, err := ParseCaBundleFromFile("testdata/cert.pem", "", "pem")
	// CertPool structures are not particularly informative, so we just check for non-nil
	assert.NotNil(t, certPool)
	assert.NoError(t, err)

	certPool, err = ParseCaBundleFromFile("testdata/mozilla-2024-10-01.pem", "", "pem")
	assert.NotNil(t, certPool)
	assert.NoError(t, err)

	certPool, err = ParseCaBundleFromFile("testdata/cacerts-java", "", "jks")
	assert.NotNil(t, certPool)
	assert.NoError(t, err)
}

func TestExtractLeafAndIntermediatesPem(t *testing.T) {
	certs, err := ReadCertificatesFromFile("testdata/aws-fullchain.pem", "pem", "")
	assert.NoError(t, err)
	leaf, intermediates, err := ExtractLeafAndIntermediates(certs)
	assert.NoError(t, err)
	require.NotNil(t, leaf)
	assert.Equal(t, "aws.amazon.com", leaf.Subject.CommonName)
	assert.NotNil(t, intermediates)
}

func TestExtractLeafAndIntermediatesDer(t *testing.T) {
	certs, err := ReadCertificatesFromFile("testdata/encrypted_chain.p12", "der", "password123")
	assert.NoError(t, err)
	leaf, intermediates, err := ExtractLeafAndIntermediates(certs)
	assert.NoError(t, err)
	require.NotNil(t, leaf)
	assert.Equal(t, "leaf.example.com", leaf.Subject.CommonName)
	assert.NotNil(t, intermediates)
}
