package x509svid_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/test/wlapitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/defakto-security/spiffecli/internal/x509svid"
)

func TestX509SVIDClient_RequestX509SVID_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	certFile := dir + "/cert.pem"

	client := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Filename:          certFile,
	}

	err := client.RequestX509SVID(ctx)
	require.NoError(t, err)

	// Verify cert was written to file
	content, err := os.ReadFile(certFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.Contains(t, string(content), "BEGIN CERTIFICATE")

	// Verify key file was also written: cert.pem → cert-key.pem
	parts := strings.SplitN(certFile, ".", 2)
	keyFile := parts[0] + "-key." + parts[1]
	keyContent, err := os.ReadFile(keyFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.Contains(t, string(keyContent), "BEGIN")
}

func TestX509SVIDClient_RequestX509SVID_DERFormat(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	certFile := dir + "/cert.der"

	client := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Filename:          certFile,
		Format:            "der",
	}

	err := client.RequestX509SVID(ctx)
	require.NoError(t, err)

	// DER output should not be PEM-encoded
	content, err := os.ReadFile(certFile) //nolint:gosec // test file path
	require.NoError(t, err)
	assert.NotContains(t, string(content), "BEGIN CERTIFICATE")
	assert.NotEmpty(t, content)
}

func TestX509SVIDClient_RequestX509SVID_InvalidFormat(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Format:            "invalid",
	}

	err := client.RequestX509SVID(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestX509SVIDClient_Verifyx509SVID_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First fetch a cert from the server
	dir := t.TempDir()
	certFile := dir + "/cert.pem"

	requestClient := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Filename:          certFile,
	}
	require.NoError(t, requestClient.RequestX509SVID(ctx))

	// Verify the cert against the same server
	verifyClient := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Filename:          certFile,
	}
	err := verifyClient.Verifyx509SVID(ctx)
	require.NoError(t, err)
}

func TestX509SVIDClient_Verifyx509SVID_InvalidCert(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &x509svid.X509SVIDClient{
		WorkloadAPISocket: socketAddr,
		Filename:          "/nonexistent/cert.pem",
	}
	err := client.Verifyx509SVID(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get certificate chain")
}
