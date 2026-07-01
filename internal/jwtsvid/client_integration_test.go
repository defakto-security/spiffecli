package jwtsvid

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/defakto-security/spiffecli/internal/test/wlapitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTSVIDClient_ValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		client  JWTSVIDClient
		wantErr string
	}{
		{
			name:    "no audiences",
			client:  JWTSVIDClient{},
			wantErr: "must specify a list of audiences",
		},
		{
			name:    "bundle source without trust domain",
			client:  JWTSVIDClient{Audiences: fakeAudience, BundleSource: "file.json"},
			wantErr: "trust domain must be specified",
		},
		{
			name:   "valid with audiences only",
			client: JWTSVIDClient{Audiences: fakeAudience},
		},
		{
			name:   "valid with bundle source and trust domain",
			client: JWTSVIDClient{Audiences: fakeAudience, BundleSource: "file.json", TrustDomain: "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.validateOptions()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestJWTSVIDClient_RequestJWTSVID_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	filename := dir + "/token.jwt"

	client := &JWTSVIDClient{
		WorkloadAPISocket: socketAddr,
		Audiences:         fakeAudience,
		Filename:          filename,
	}

	err := client.RequestJWTSVID(ctx)
	require.NoError(t, err)

	// Verify token was written to file
	content, err := os.ReadFile(filename) //nolint:gosec // test file path
	require.NoError(t, err)
	// JWT tokens have 3 parts separated by dots
	assert.Contains(t, string(content), ".")
}

func TestJWTSVIDClient_RequestJWTSVID_InvalidOptions(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &JWTSVIDClient{
		WorkloadAPISocket: socketAddr,
		// No audiences - should fail validation
	}

	err := client.RequestJWTSVID(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a list of audiences")
}

func TestJWTSVIDClient_VerifyJWTSVID_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Fetch JWT bundle and write to temp file
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	require.NoError(t, err)
	td, err := jwtSource.GetJWTBundleForTrustDomain(wlapitest.TrustDomain())
	require.NoError(t, err)
	bundleBytes, err := td.Marshal()
	require.NoError(t, err)
	_ = jwtSource.Close()

	dir := t.TempDir()
	bundleFile := dir + "/bundle.jwks"
	require.NoError(t, os.WriteFile(bundleFile, bundleBytes, 0600))

	// Fetch JWT SVID token
	tokenFile := dir + "/token.jwt"
	requestClient := &JWTSVIDClient{
		WorkloadAPISocket: socketAddr,
		Audiences:         fakeAudience,
		Filename:          tokenFile,
	}
	require.NoError(t, requestClient.RequestJWTSVID(ctx))

	// Verify JWT SVID using the bundle file
	verifyClient := &JWTSVIDClient{
		Audiences:    fakeAudience,
		Filename:     tokenFile,
		BundleSource: bundleFile,
		TrustDomain:  "example.com",
	}
	err = verifyClient.VerifyJWTSVID(ctx)
	require.NoError(t, err)
}

func TestJWTSVIDClient_VerifyJWTSVID_InvalidToken(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Fetch JWT bundle
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	require.NoError(t, err)
	td, err := jwtSource.GetJWTBundleForTrustDomain(wlapitest.TrustDomain())
	require.NoError(t, err)
	bundleBytes, err := td.Marshal()
	require.NoError(t, err)
	_ = jwtSource.Close()

	dir := t.TempDir()
	bundleFile := dir + "/bundle.jwks"
	require.NoError(t, os.WriteFile(bundleFile, bundleBytes, 0600))

	verifyClient := &JWTSVIDClient{ //nolint:gosec // fake test credentials
		Audiences:    fakeAudience,
		Token:        "not.a.valid.jwt",
		BundleSource: bundleFile,
		TrustDomain:  "example.com",
	}
	err = verifyClient.VerifyJWTSVID(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to validate")
}

func TestJWTSVIDClient_RequestJWTSVID_MultipleAudiences(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &JWTSVIDClient{
		WorkloadAPISocket: socketAddr,
		Audiences:         fakeAudiences,
		Decode:            true,
	}

	// Capture stdout
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	err = client.RequestJWTSVID(ctx)

	_ = w.Close()
	os.Stdout = origStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Decoded output should be JSON containing the SPIFFE ID
	assert.Contains(t, output, "spiffe://example.com/test")
}
