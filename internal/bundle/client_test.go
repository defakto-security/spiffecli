package bundle

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/test/wlapitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundleClient_VerifyOptions(t *testing.T) {
	tests := []struct {
		name    string
		client  BundleClient
		wantErr string
	}{
		{
			name:    "missing trust domain",
			client:  BundleClient{},
			wantErr: "must set the --trust-domain flag",
		},
		{
			name:   "valid",
			client: BundleClient{TrustDomain: "example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.verifyOptions()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBundleClient_OutputBundle(t *testing.T) {
	// Use a mock bundle that implements Bundle interface
	t.Run("outputs to writer when no filename", func(t *testing.T) {
		client := &BundleClient{}
		mock := &mockBundle{data: []byte(`{"keys":[]}`)}

		var buf bytes.Buffer
		err := client.outputBundle(mock, &buf)
		require.NoError(t, err)
		assert.Contains(t, buf.String(), `{"keys":[]}`)
	})

	t.Run("writes to file when filename set", func(t *testing.T) {
		dir := t.TempDir()
		filename := dir + "/bundle.json"
		client := &BundleClient{Filename: filename}
		mock := &mockBundle{data: []byte(`{"keys":[]}`)}

		err := client.outputBundle(mock, os.Stdout)
		require.NoError(t, err)

		content, err := os.ReadFile(filename) //nolint:gosec // test file path
		require.NoError(t, err)
		assert.Equal(t, `{"keys":[]}`, string(content))
	})

	t.Run("returns error on marshal failure", func(t *testing.T) {
		client := &BundleClient{}
		mock := &mockBundle{err: assert.AnError}

		var buf bytes.Buffer
		err := client.outputBundle(mock, &buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal bundle")
	})
}

type mockBundle struct {
	data []byte
	err  error
}

func (m *mockBundle) Marshal() ([]byte, error) {
	return m.data, m.err
}

func TestBundleClient_GetX509Bundle_MissingTrustDomain(t *testing.T) {
	client := &BundleClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.GetX509Bundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must set the --trust-domain flag")
}

func TestBundleClient_GetJWTBundle_MissingTrustDomain(t *testing.T) {
	client := &BundleClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.GetJWTBundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must set the --trust-domain flag")
}

func TestBundleClient_GetX509Bundle_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &BundleClient{
		WorkloadAPISocket: socketAddr,
		TrustDomain:       "example.com",
	}

	// Redirect stdout capture - use Filename to capture output
	dir := t.TempDir()
	client.Filename = dir + "/bundle.json"

	err := client.GetX509Bundle(ctx)
	require.NoError(t, err)

	content, err := os.ReadFile(client.Filename) //nolint:gosec // test temp path
	require.NoError(t, err)
	// X.509 bundles are PEM-encoded certificates
	assert.Contains(t, string(content), "BEGIN CERTIFICATE")
}

func TestBundleClient_GetJWTBundle_Integration(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	client := &BundleClient{
		WorkloadAPISocket: socketAddr,
		TrustDomain:       "example.com",
		Filename:          dir + "/jwt-bundle.json",
	}

	err := client.GetJWTBundle(ctx)
	require.NoError(t, err)

	content, err := os.ReadFile(client.Filename) //nolint:gosec // test temp path
	require.NoError(t, err)
	assert.Contains(t, string(content), "keys")
}

func TestBundleClient_GetX509Bundle_InvalidTrustDomain(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := &BundleClient{
		WorkloadAPISocket: socketAddr,
		TrustDomain:       "not a valid trust domain!!!",
	}

	err := client.GetX509Bundle(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse trust domain")
}
