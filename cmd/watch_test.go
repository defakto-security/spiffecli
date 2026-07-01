package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestWatchCmd builds a standalone watch command tree for unit tests,
// mirroring the structure assembled by init() in watch.go without relying
// on the shared rootCmd or the unexported watchCmd.
func newTestWatchCmd() *cobra.Command {
	watchCmd := &cobra.Command{
		Use:          "watch",
		Short:        "Watch for SVID or bundle updates from the Workload API",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if socketValue(cmd) == "" {
				return errors.New("must specify flag --spiffe-endpoint-socket")
			}
			return nil
		},
	}
	addSocketFlag(watchCmd)
	watchCmd.AddCommand(NewWatchX509SVIDCmd())
	watchCmd.AddCommand(NewWatchJWTSVIDCmd())
	watchCmd.AddCommand(NewWatchBundleCmd())
	return watchCmd
}

func TestNewWatchX509SVIDCmd_Properties(t *testing.T) {
	cmd := NewWatchX509SVIDCmd()
	assert.Equal(t, "x509-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("format"))
}

func TestNewWatchJWTSVIDCmd_Properties(t *testing.T) {
	cmd := NewWatchJWTSVIDCmd()
	assert.Equal(t, "jwt-svid", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.Flags().Lookup("audiences"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("interval"))
}

func TestNewWatchBundleCmd_Properties(t *testing.T) {
	cmd := NewWatchBundleCmd()
	assert.Equal(t, "bundle TYPE", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)
	assert.NotNil(t, cmd.Flags().Lookup("format"))
}

func TestWatchX509SVIDCmd_MissingSocket(t *testing.T) {
	t.Setenv(socketEnvVar, "")
	watchCmd := newTestWatchCmd()
	watchCmd.SetArgs([]string{"x509-svid"})
	err := watchCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify flag --spiffe-endpoint-socket")
}

func TestWatchJWTSVIDCmd_MissingSocket(t *testing.T) {
	t.Setenv(socketEnvVar, "")
	watchCmd := newTestWatchCmd()
	watchCmd.SetArgs([]string{"jwt-svid"})
	err := watchCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify flag --spiffe-endpoint-socket")
}

func TestWatchBundleCmd_MissingSocket(t *testing.T) {
	t.Setenv(socketEnvVar, "")
	watchCmd := newTestWatchCmd()
	watchCmd.SetArgs([]string{"bundle", "x509"})
	err := watchCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify flag --spiffe-endpoint-socket")
}

// TestWatchSocketGuard_PassesWhenEnvSet verifies that PersistentPreRunE allows
// execution when SPIFFE_ENDPOINT_SOCKET is set, without spawning a goroutine or
// dialling gRPC.
func TestWatchSocketGuard_PassesWhenEnvSet(t *testing.T) {
	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")
	watchCmd := newTestWatchCmd()
	sub := watchCmd.Commands()[0] // x509-svid (first registered subcommand)
	require.NotNil(t, sub)
	require.NotNil(t, sub.Parent().PersistentPreRunE)
	err := sub.Parent().PersistentPreRunE(sub, nil)
	require.NoError(t, err)
}

func TestWatchJWTSVIDCmd_MissingAudiences(t *testing.T) {
	t.Setenv(socketEnvVar, "unix:///tmp/test.sock")
	watchCmd := newTestWatchCmd()
	watchCmd.SetArgs([]string{"jwt-svid"})
	err := watchCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify --audiences")
}
