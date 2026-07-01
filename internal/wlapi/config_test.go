package wlapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_ValidMinimal(t *testing.T) {
	configPath := filepath.Join("testdata", "valid-minimal.toml")
	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Verify trust domain was parsed
	require.Len(t, config.TrustDomains, 1)
	td := config.TrustDomains[0]
	assert.Equal(t, "example.com", td.Name.String())

	// Verify default TTLs were applied
	assert.Equal(t, DefaultX509AuthorityTTL, td.X509AuthorityTTL)
	assert.Equal(t, DefaultJWTAuthorityTTL, td.JWTAuthorityTTL)

	// Verify workload was parsed
	require.Len(t, td.Workloads, 1)
	wl := td.Workloads[0]
	assert.Equal(t, "spiffe://example.com/frontend", wl.ID.String())

	// Verify default workload TTLs were applied
	assert.Equal(t, DefaultWorkloadX509SVIDTTL, wl.X509SVIDTTL)
	assert.Equal(t, DefaultWorkloadX509SVIDRotateAt, wl.X509SVIDRotateAt)
	assert.Equal(t, DefaultWorkloadJWTSVIDTTL, wl.JWTSVIDTTL)

	// Verify default socket path was generated
	expectedSocketPath := filepath.Join(os.TempDir(), "spirl-dev", "example.com", "frontend.sock")
	assert.Equal(t, expectedSocketPath, wl.SocketPath)
}

func TestLoadConfig_ValidFull(t *testing.T) {
	configPath := filepath.Join("testdata", "valid-full.toml")
	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Verify federation config
	assert.Equal(t, 8080, config.Federation.Port)

	// Verify trust domain
	require.Len(t, config.TrustDomains, 1)
	td := config.TrustDomains[0]
	assert.Equal(t, "example.com", td.Name.String())

	// Verify custom TTLs were applied
	assert.Equal(t, 48*time.Hour, td.X509AuthorityTTL)
	assert.Equal(t, 72*time.Hour, td.JWTAuthorityTTL)

	// Verify workloads
	require.Len(t, td.Workloads, 2)

	// Frontend workload with all custom values
	frontend := findWorkload(t, td.Workloads, "spiffe://example.com/custom/frontend")
	require.NotNil(t, frontend)
	assert.Equal(t, "/tmp/frontend.sock", frontend.SocketPath)
	assert.Equal(t, 2*time.Hour, frontend.X509SVIDTTL)
	assert.Equal(t, 20*time.Minute, frontend.X509SVIDRotateAt)
	assert.Equal(t, 3*time.Hour, frontend.JWTSVIDTTL)

	// Backend workload with defaults
	backend := findWorkload(t, td.Workloads, "spiffe://example.com/backend")
	require.NotNil(t, backend)
	assert.Equal(t, DefaultWorkloadX509SVIDTTL, backend.X509SVIDTTL)
	assert.Equal(t, DefaultWorkloadX509SVIDRotateAt, backend.X509SVIDRotateAt)
	assert.Equal(t, DefaultWorkloadJWTSVIDTTL, backend.JWTSVIDTTL)
}

func TestLoadConfig_InvalidSyntax(t *testing.T) {
	configPath := filepath.Join("testdata", "invalid-syntax.toml")
	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding config")
}

func TestLoadConfig_UnknownField(t *testing.T) {
	configPath := filepath.Join("testdata", "unknown-field.toml")
	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding config")
}

func TestLoadConfig_InvalidWorkloadName(t *testing.T) {
	configPath := filepath.Join("testdata", "invalid-workload-name.toml")
	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid workload name")
}

func TestLoadConfig_InvalidIDPath(t *testing.T) {
	configPath := filepath.Join("testdata", "invalid-id-path.toml")
	_, err := LoadConfig(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid id_path")
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("nonexistent.toml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading config file")
}

func TestLoadConfig_MultiTrustDomain(t *testing.T) {
	// Create a temporary config with multiple trust domains
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "multi-td.toml")
	configContent := `
[td."example.com"]
[td."example.com".workload.frontend]

[td."acme-corp"]
[td."acme-corp".workload.backend]
`
	err := os.WriteFile(configPath, []byte(configContent), 0644) //nolint:gosec // test config file
	require.NoError(t, err)

	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Verify both trust domains were parsed
	require.Len(t, config.TrustDomains, 2)

	// Find each trust domain
	exampleCom := findTrustDomain(t, config.TrustDomains, "example.com")
	require.NotNil(t, exampleCom)
	require.Len(t, exampleCom.Workloads, 1)
	assert.Equal(t, "spiffe://example.com/frontend", exampleCom.Workloads[0].ID.String())

	acmeCorp := findTrustDomain(t, config.TrustDomains, "acme-corp")
	require.NotNil(t, acmeCorp)
	require.Len(t, acmeCorp.Workloads, 1)
	assert.Equal(t, "spiffe://acme-corp/backend", acmeCorp.Workloads[0].ID.String())
}

func TestLoadConfig_CustomIDPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "custom-id-path.toml")
	configContent := `
[td."example.com"]
[td."example.com".workload.myservice]
id_path = "/services/v1/myservice"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644) //nolint:gosec // test config file
	require.NoError(t, err)

	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	require.Len(t, config.TrustDomains, 1)
	require.Len(t, config.TrustDomains[0].Workloads, 1)
	wl := config.TrustDomains[0].Workloads[0]
	assert.Equal(t, "spiffe://example.com/services/v1/myservice", wl.ID.String())
}

func TestLoadConfig_DefaultSocketPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "default-socket.toml")
	configContent := `
[td."example.com"]
[td."example.com".workload.frontend]
`
	err := os.WriteFile(configPath, []byte(configContent), 0644) //nolint:gosec // test config file
	require.NoError(t, err)

	config, err := LoadConfig(configPath)
	require.NoError(t, err)

	require.Len(t, config.TrustDomains, 1)
	require.Len(t, config.TrustDomains[0].Workloads, 1)
	wl := config.TrustDomains[0].Workloads[0]

	// Verify socket path follows expected pattern
	expectedSocketPath := filepath.Join(os.TempDir(), "spirl-dev", "example.com", "frontend.sock")
	assert.Equal(t, expectedSocketPath, wl.SocketPath)
}

func TestLoadConfig_DurationParsing(t *testing.T) {
	cases := []struct {
		name        string
		tomlContent string
		checkFunc   func(t *testing.T, config Config)
	}{
		{
			name: "hours",
			tomlContent: `
[td."example.com"]
x509_authority_ttl = "2h"
jwt_authority_ttl = "3h"
[td."example.com".workload.frontend]
x509_svid_ttl = "30m"
`,
			checkFunc: func(t *testing.T, config Config) {
				td := config.TrustDomains[0]
				assert.Equal(t, 2*time.Hour, td.X509AuthorityTTL)
				assert.Equal(t, 3*time.Hour, td.JWTAuthorityTTL)
				assert.Equal(t, 30*time.Minute, td.Workloads[0].X509SVIDTTL)
			},
		},
		{
			name: "complex duration",
			tomlContent: `
[td."example.com"]
x509_authority_ttl = "1h30m45s"
[td."example.com".workload.frontend]
`,
			checkFunc: func(t *testing.T, config Config) {
				td := config.TrustDomains[0]
				expected := 1*time.Hour + 30*time.Minute + 45*time.Second
				assert.Equal(t, expected, td.X509AuthorityTTL)
			},
		},
		{
			name: "zero duration defaults",
			tomlContent: `
[td."example.com"]
x509_authority_ttl = "0s"
[td."example.com".workload.frontend]
`,
			checkFunc: func(t *testing.T, config Config) {
				td := config.TrustDomains[0]
				// Zero duration should be replaced with default
				assert.Equal(t, DefaultX509AuthorityTTL, td.X509AuthorityTTL)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test.toml")
			err := os.WriteFile(configPath, []byte(tc.tomlContent), 0644) //nolint:gosec // test config file
			require.NoError(t, err)

			config, err := LoadConfig(configPath)
			require.NoError(t, err)

			tc.checkFunc(t, config)
		})
	}
}

// Helper functions

func findWorkload(t *testing.T, workloads []WorkloadConfig, spiffeID string) *WorkloadConfig {
	t.Helper()
	for i := range workloads {
		if workloads[i].ID.String() == spiffeID {
			return &workloads[i]
		}
	}
	return nil
}

func findTrustDomain(t *testing.T, trustDomains []TrustDomainConfig, name string) *TrustDomainConfig {
	t.Helper()
	expectedTD, err := spiffeid.TrustDomainFromString(name)
	require.NoError(t, err)

	for i := range trustDomains {
		if trustDomains[i].Name == expectedTD {
			return &trustDomains[i]
		}
	}
	return nil
}
