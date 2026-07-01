//go:build !windows

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E_GetX509SVID(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	outputFile := t.TempDir() + "/cert.pem"

	cmd := exec.Command(binary, "get", "x509-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--filename", outputFile,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get x509-svid failed: %s", out)

	// Verify certificate file was created with PEM content
	certBytes, err := os.ReadFile(outputFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.Contains(t, string(certBytes), "BEGIN CERTIFICATE")

	// Verify key file was created alongside cert
	keyFile := strings.TrimSuffix(outputFile, ".pem") + "-key.pem"
	keyBytes, err := os.ReadFile(keyFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.Contains(t, string(keyBytes), "BEGIN")
}

func TestE2E_GetX509SVID_DER(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	outputFile := t.TempDir() + "/cert.der"

	cmd := exec.Command(binary, "get", "x509-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--filename", outputFile,
		"--format", "der",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get x509-svid --format der failed: %s", out)

	// DER output should not be PEM
	certBytes, err := os.ReadFile(outputFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.NotContains(t, string(certBytes), "BEGIN CERTIFICATE")
	assert.NotEmpty(t, certBytes)
}

func TestE2E_GetJWTSVID(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	cmd := exec.Command(binary, "get", "jwt-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--audiences", "test-audience",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get jwt-svid failed: %s", out)

	// JWT token has 3 dot-separated parts
	token := strings.TrimSpace(string(out))
	assert.Equal(t, 3, strings.Count(token, ".")+1, // count dots + 1 = parts
		"expected JWT token format (3 parts), got: %s", token)
}

func TestE2E_GetJWTSVID_Decode(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	cmd := exec.Command(binary, "get", "jwt-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--audiences", "test-audience",
		"--decode",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get jwt-svid --decode failed: %s", out)

	// Decoded output should be JSON with SPIFFE ID
	output := string(out)
	assert.Contains(t, output, "spiffe://example.com")
}

func TestE2E_GetBundle_JWT(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	cmd := exec.Command(binary, "get", "bundle", "jwt", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--trust-domain", "example.com",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get bundle jwt failed: %s", out)

	// JWT bundle is JWKS JSON with keys
	assert.Contains(t, string(out), "keys")
}

func TestE2E_GetBundle_X509(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	cmd := exec.Command(binary, "get", "bundle", "x509", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--trust-domain", "example.com",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "get bundle x509 failed: %s", out)

	// X.509 bundle is PEM
	assert.Contains(t, string(out), "BEGIN CERTIFICATE")
}

func TestE2E_Get_MissingSocket(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "get", "x509-svid") //nolint:gosec // intentional subprocess in test
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify flag --spiffe-endpoint-socket")
}