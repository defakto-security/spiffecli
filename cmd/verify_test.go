package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVerifyJWTSVIDCmd_Properties(t *testing.T) {
	cmd := NewVerifyJWTSVIDCmd()
	assert.Equal(t, "jwt-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("token"))
	assert.NotNil(t, cmd.Flags().Lookup("audiences"))
	assert.NotNil(t, cmd.Flags().Lookup("bundle"))
	assert.NotNil(t, cmd.Flags().Lookup("trust-domain"))
}

func TestNewVerifyJWTSVIDCmd_MissingSocketAndBundle(t *testing.T) {
	cmd := NewVerifyJWTSVIDCmd()

	// Neither socket nor bundle set
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify flag --spiffe-endpoint-socket or --bundle")
}

func TestNewVerifyJWTSVIDCmd_WithBundle_NoAudiences(t *testing.T) {
	cmd := NewVerifyJWTSVIDCmd()

	require.NoError(t, cmd.Flags().Set("bundle", "../internal/bundle/testdata/single.jwks"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	// Should fail at JWT validation level (no audiences or token)
	assert.NotNil(t, err)
}

func TestNewVerifyX509SVIDCmd_Properties(t *testing.T) {
	cmd := NewVerifyX509SVIDCmd()
	assert.Equal(t, "x509-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("password"))
}

func TestNewVerifyX509SVIDCmd_MissingSocket(t *testing.T) {
	cmd := NewVerifyX509SVIDCmd()

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify flag --spiffe-endpoint-socket")
}

func TestNewVerifyX509Cmd_Properties(t *testing.T) {
	cmd := NewVerifyX509Cmd()
	assert.Equal(t, "x509", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("certificate"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("ca-bundle"))
	assert.NotNil(t, cmd.Flags().Lookup("system"))
	assert.NotNil(t, cmd.Flags().Lookup("root-program"))
	assert.NotNil(t, cmd.Flags().Lookup("show-path"))
}

func TestNewVerifyX509Cmd_NoCABundle(t *testing.T) {
	cmd := NewVerifyX509Cmd()

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a CA bundle")
}

func TestNewVerifyX509Cmd_MultipleCAOptions(t *testing.T) {
	cmd := NewVerifyX509Cmd()

	require.NoError(t, cmd.Flags().Set("system", "true"))
	require.NoError(t, cmd.Flags().Set("ca-bundle", "bundle.pem"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of")
}

func TestNewVerifyX509Cmd_WithRootProgram(t *testing.T) {
	cmd := NewVerifyX509Cmd()

	require.NoError(t, cmd.Flags().Set("root-program", "mozilla"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	// Should fail at VerifyCertificate (no cert specified), not at PreRunE
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must specify a CA bundle")
}

func TestNewVerifyX509Cmd_WithSystem(t *testing.T) {
	cmd := NewVerifyX509Cmd()

	require.NoError(t, cmd.Flags().Set("system", "true"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	// Should fail at VerifyCertificate (no cert specified)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must specify a CA bundle")
}

func TestNewVerifyJWTSVIDCmd_BundleAndSocket_SkipsSocketAssignment(t *testing.T) {
	cmd, client := newVerifyJWTSVIDCmdWithClient()

	require.NoError(t, cmd.Flags().Set("bundle", "../internal/bundle/testdata/single.jwks"))
	require.NoError(t, cmd.Flags().Set(endpointSocketKey, "unix:///tmp/test.sock"))
	require.NoError(t, cmd.Flags().Set("audiences", "spiffe://example.org/svc"))
	require.NoError(t, cmd.Flags().Set("trust-domain", "example.org"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()

	// When bundle is provided, WorkloadAPISocket must not be assigned.
	assert.Equal(t, "", client.WorkloadAPISocket, "WorkloadAPISocket should remain empty when bundle is set")

	// The error must originate from the JWT token path, not from a socket dial.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not get token", "expected JWT-path error")
	assert.NotContains(t, err.Error(), "unable to create JWTSource")
	assert.NotContains(t, err.Error(), "workload API")
	assert.NotContains(t, err.Error(), "connect")
}

func TestNewVerifyJWTSVIDCmd_UsesPreRunE(t *testing.T) {
	cmd := NewVerifyJWTSVIDCmd()
	assert.NotNil(t, cmd.PreRunE, "jwt-svid must wire validation via PreRunE")
	assert.Nil(t, cmd.PersistentPreRunE, "jwt-svid must not use PersistentPreRunE (chaining hazard)")
}

func TestNewVerifyX509SVIDCmd_UsesPreRunE(t *testing.T) {
	cmd := NewVerifyX509SVIDCmd()
	assert.NotNil(t, cmd.PreRunE, "x509-svid must wire validation via PreRunE")
	assert.Nil(t, cmd.PersistentPreRunE, "x509-svid must not use PersistentPreRunE (chaining hazard)")
}

func TestNewVerifyX509SVIDCmd_WithSocket_NoFile(t *testing.T) {
	cmd := NewVerifyX509SVIDCmd()

	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	// Fails at socket connection before reaching file validation
	assert.Contains(t, err.Error(), "failed to verify x509 SVID")
}
