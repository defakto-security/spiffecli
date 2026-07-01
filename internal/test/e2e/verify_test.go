//go:build !windows

package e2e

import (
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E_VerifyX509SVID(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	// First get the x509 SVID
	certFile := t.TempDir() + "/cert.pem"
	getCmd := exec.Command(binary, "get", "x509-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--filename", certFile,
	)
	out, err := getCmd.CombinedOutput()
	require.NoError(t, err, "get x509-svid failed: %s", out)

	// Then verify it
	verifyCmd := exec.Command(binary, "verify", "x509-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--filename", certFile,
	)
	out, err = verifyCmd.CombinedOutput()
	require.NoError(t, err, "verify x509-svid failed: %s", out)
}

func TestE2E_VerifyJWTSVID(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	// Get a JWT SVID token to a file
	tokenFile := t.TempDir() + "/token.jwt"
	getCmd := exec.Command(binary, "get", "jwt-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--audiences", "test-audience",
		"--filename", tokenFile,
	)
	out, err := getCmd.CombinedOutput()
	require.NoError(t, err, "get jwt-svid failed: %s", out)

	// Get the JWT bundle to a file for offline verification
	bundleFile := t.TempDir() + "/bundle.jwks"
	bundleCmd := exec.Command(binary, "get", "bundle", "jwt", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--trust-domain", "example.com",
		"--filename", bundleFile,
	)
	out, err = bundleCmd.CombinedOutput()
	require.NoError(t, err, "get bundle jwt failed: %s", out)

	// Verify JWT SVID using the bundle file
	verifyCmd := exec.Command(binary, "verify", "jwt-svid", //nolint:gosec // intentional subprocess in test
		"--filename", tokenFile,
		"--audiences", "test-audience",
		"--bundle", bundleFile,
		"--trust-domain", "example.com",
	)
	out, err = verifyCmd.CombinedOutput()
	require.NoError(t, err, "verify jwt-svid failed: %s", out)
}

func TestE2E_VerifyX509_WithCABundle(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	// Get x509 SVID and the x509 bundle
	certFile := t.TempDir() + "/cert.pem"
	getCmd := exec.Command(binary, "get", "x509-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--filename", certFile,
	)
	out, err := getCmd.CombinedOutput()
	require.NoError(t, err, "get x509-svid failed: %s", out)

	bundleFile := t.TempDir() + "/bundle.pem"
	bundleCmd := exec.Command(binary, "get", "bundle", "x509", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--trust-domain", "example.com",
		"--filename", bundleFile,
	)
	out, err = bundleCmd.CombinedOutput()
	require.NoError(t, err, "get bundle x509 failed: %s", out)

	// Verify x509 cert against the CA bundle
	verifyCmd := exec.Command(binary, "verify", "x509", //nolint:gosec // intentional subprocess in test
		"--certificate", certFile,
		"--ca-bundle", bundleFile,
	)
	out, err = verifyCmd.CombinedOutput()
	require.NoError(t, err, "verify x509 failed: %s", out)
}

func TestE2E_VerifyX509_MissingCABundle(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "verify", "x509", //nolint:gosec // intentional subprocess in test
		"--certificate", "cert.pem",
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify a CA bundle")
}