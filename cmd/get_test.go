package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBundleCmd_Properties(t *testing.T) {
	cmd := NewBundleCmd()
	assert.Equal(t, "bundle FORMAT", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	// Verify flags exist
	assert.NotNil(t, cmd.Flags().Lookup("trust-domain"))
	assert.NotNil(t, cmd.Flags().Lookup("filename"))
}

func TestNewBundleCmd_NoArgs(t *testing.T) {
	cmd := NewBundleCmd()
	cmd.SetArgs([]string{})

	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify bundle format")
}

func TestNewBundleCmd_InvalidFormat(t *testing.T) {
	cmd := NewBundleCmd()
	cmd.SetArgs([]string{"badformat"})

	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify valid bundle format")
}

func TestNewJWTSVIDCmd_Properties(t *testing.T) {
	cmd := NewJWTSVIDCmd()
	assert.Equal(t, "jwt-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("decode"))
	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("audiences"))
}

func TestNewX509SVIDCmd_Properties(t *testing.T) {
	cmd := NewX509SVIDCmd()
	assert.Equal(t, "x509-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
}

func TestNewX509SVIDCmd_InvalidFormat(t *testing.T) {
	cmd := NewX509SVIDCmd()

	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")

	require.NoError(t, cmd.Flags().Set("format", "badformat"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestNewJWTSVIDCmd_NoAudiences(t *testing.T) {
	cmd := NewJWTSVIDCmd()

	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a list of audiences")
}

func TestNewBundleCmd_ValidJWTFormat(t *testing.T) {
	cmd := NewBundleCmd()
	cmd.SetArgs([]string{"jwt"})

	t.Setenv(socketEnvVar, "unix:///tmp/nonexistent.sock")

	err := cmd.Execute()
	// Should fail connecting to nonexistent socket, not at format validation
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must specify valid bundle format")
}

func TestNewBundleCmd_ValidX509Format(t *testing.T) {
	cmd := NewBundleCmd()
	cmd.SetArgs([]string{"x509"})

	t.Setenv(socketEnvVar, "unix:///tmp/nonexistent.sock")

	err := cmd.Execute()
	// Should fail connecting to nonexistent socket
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must specify valid bundle format")
}

func TestNewBundleCmd_SocketViaFlag(t *testing.T) {
	// Explicitly clear the env var so only the cobra flag branch can resolve the socket.
	t.Setenv(socketEnvVar, "")

	parent := &cobra.Command{Use: "get", SilenceErrors: true, SilenceUsage: true}
	addSocketFlag(parent)
	parent.AddCommand(NewBundleCmd())
	parent.SetArgs([]string{"bundle", "--spiffe-endpoint-socket=unix:///tmp/nonexistent.sock", "jwt"})

	err := parent.Execute()
	// Should fail connecting to the nonexistent socket — the socket was resolved via
	// the cobra flag, not the env var.
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "must specify valid bundle format")
	assert.NotContains(t, err.Error(), "must specify flag --spiffe-endpoint-socket")
}
