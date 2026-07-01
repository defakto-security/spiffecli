package cmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCmd() *cobra.Command {
	return &cobra.Command{Use: "test", RunE: func(cmd *cobra.Command, args []string) error { return nil }}
}

func TestSocketValue_PersistentFlagWinsOverEnv(t *testing.T) {
	var captured string

	parent := &cobra.Command{Use: "parent"}
	addSocketFlag(parent)

	child := &cobra.Command{
		Use: "child",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = socketValue(cmd)
			return nil
		},
	}
	parent.AddCommand(child)
	parent.SetArgs([]string{"child", "--spiffe-endpoint-socket=unix:///from/flag"})

	t.Setenv(socketEnvVar, "unix:///from/env")
	require.NoError(t, parent.Execute())
	assert.Equal(t, "unix:///from/flag", captured)
}

func TestSocketValue_EnvFallback(t *testing.T) {
	cmd := newTestCmd()
	addSocketFlag(cmd)

	t.Setenv(socketEnvVar, "unix:///from/env")

	assert.Equal(t, "unix:///from/env", socketValue(cmd))
}


func TestSocketValue_Neither(t *testing.T) {
	cmd := newTestCmd()
	addSocketFlag(cmd)

	assert.Equal(t, "", socketValue(cmd))
}

func TestSocketValue_LocalFlagWinsOverEnv(t *testing.T) {
	var captured string

	cmd := &cobra.Command{
		Use: "test",
		RunE: func(c *cobra.Command, args []string) error {
			captured = socketValue(c)
			return nil
		},
	}
	addSocketFlagLocal(cmd)
	cmd.SetArgs([]string{"--spiffe-endpoint-socket=unix:///from/flag"})

	t.Setenv(socketEnvVar, "unix:///from/env")
	require.NoError(t, cmd.Execute())
	assert.Equal(t, "unix:///from/flag", captured)
}

func TestSocketValue_LocalFlagEnvFallback(t *testing.T) {
	cmd := newTestCmd()
	addSocketFlagLocal(cmd)

	t.Setenv(socketEnvVar, "unix:///from/env")

	assert.Equal(t, "unix:///from/env", socketValue(cmd))
}

func TestAddSocketFlag_RegistersCorrectly(t *testing.T) {
	cmd := newTestCmd()
	addSocketFlag(cmd)

	f := cmd.PersistentFlags().Lookup(endpointSocketKey)
	require.NotNil(t, f)
	assert.Equal(t, "s", f.Shorthand)
	assert.Contains(t, f.Usage, socketEnvVar)
}

func TestAddSocketFlagLocal_RegistersCorrectly(t *testing.T) {
	cmd := newTestCmd()
	addSocketFlagLocal(cmd)

	f := cmd.Flags().Lookup(endpointSocketKey)
	require.NotNil(t, f)
	assert.Equal(t, "s", f.Shorthand)
	assert.Contains(t, f.Usage, socketEnvVar)
}

func TestRootCmd_NoSocketFlag(t *testing.T) {
	assert.Nil(t, rootCmd.PersistentFlags().Lookup(endpointSocketKey),
		"rootCmd should not have --spiffe-endpoint-socket as a persistent flag")
}

func TestSocketFlagScope_AbsentOnOfflineCommands(t *testing.T) {
	offlineCommands := []struct {
		name string
		path []string
	}{
		{"inspect jwt", []string{"inspect", "jwt"}},
		{"inspect jwks", []string{"inspect", "jwks"}},
		{"inspect x509", []string{"inspect", "x509"}},
		{"verify x509", []string{"verify", "x509"}},
		{"run", []string{"run"}},
		{"docs", []string{"docs"}},
	}

	onlineCommands := []struct {
		name string
		path []string
	}{
		{"get", []string{"get"}},
		{"get x509-svid", []string{"get", "x509-svid"}},
		{"get jwt-svid", []string{"get", "jwt-svid"}},
		{"get bundle", []string{"get", "bundle"}},
		{"verify x509-svid", []string{"verify", "x509-svid"}},
		{"verify jwt-svid", []string{"verify", "jwt-svid"}},
		{"watch", []string{"watch"}},
		{"watch x509-svid", []string{"watch", "x509-svid"}},
		{"watch jwt-svid", []string{"watch", "jwt-svid"}},
		{"watch bundle", []string{"watch", "bundle"}},
	}

	for _, tc := range offlineCommands {
		t.Run(tc.name, func(t *testing.T) {
			found, _, err := rootCmd.Traverse(tc.path)
			require.NoError(t, err)
			require.NotNil(t, found)
			assert.Nil(t, found.Flag(endpointSocketKey),
				"command %q should not have --spiffe-endpoint-socket flag", tc.name)
		})
	}

	for _, tc := range onlineCommands {
		t.Run(tc.name, func(t *testing.T) {
			found, _, err := rootCmd.Traverse(tc.path)
			require.NoError(t, err)
			require.NotNil(t, found)
			assert.NotNil(t, found.Flag(endpointSocketKey),
				"command %q should have --spiffe-endpoint-socket flag", tc.name)
		})
	}
}


func TestSocketValue_PersistentFlagOnParent_EnvFallback(t *testing.T) {
	var captured string

	parent := &cobra.Command{Use: "parent"}
	addSocketFlag(parent)

	child := &cobra.Command{
		Use: "child",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = socketValue(cmd)
			return nil
		},
	}
	parent.AddCommand(child)
	parent.SetArgs([]string{"child"})

	t.Setenv(socketEnvVar, "unix:///from/env")
	require.NoError(t, parent.Execute())
	assert.Equal(t, "unix:///from/env", captured)
}


func TestEnsureUnixSocketAddress(t *testing.T) {
	t.Parallel()

	testAbsPath, err := filepath.Abs("testdata")
	require.NoError(t, err)

	testCases := []struct {
		name        string
		input       string
		expected    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "path without prefix",
			input:    "/tmp/socket.sock",
			expected: "unix:///tmp/socket.sock",
		},
		{
			name:     "path with prefix",
			input:    "unix:///tmp/socket.sock",
			expected: "unix:///tmp/socket.sock",
		},
		{
			name:        "tcp:// is rejected",
			input:       "tcp://attacker.example/workload",
			wantErr:     true,
			errContains: `"tcp://"`,
		},
		{
			name:        "tcp:// error names allowed schemes",
			input:       "tcp://127.0.0.1:1234",
			wantErr:     true,
			errContains: "unix:// and npipe://",
		},
		{
			name:        "tcp:// error names SPIFFE_ENDPOINT_SOCKET",
			input:       "tcp://127.0.0.1:1234",
			wantErr:     true,
			errContains: "SPIFFE_ENDPOINT_SOCKET",
		},
		{
			name:        "http:// is rejected",
			input:       "http://example.com/workload",
			wantErr:     true,
			errContains: `"http://"`,
		},
		{
			name:        "ws:// is rejected",
			input:       "ws://example.com/workload",
			wantErr:     true,
			errContains: `"ws://"`,
		},
		{
			name:     "npipe:// is allowed",
			input:    "npipe://./pipe/agent",
			expected: "npipe://./pipe/agent",
		},
		{
			name:     "relative path",
			input:    "testdata",
			expected: "unix://" + testAbsPath,
		},
		{
			name:     "relative path with dot",
			input:    "./testdata",
			expected: "unix://" + testAbsPath,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ensureUnixSocketAddress(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSocketValue_RejectsTCPSchemeViaEnv(t *testing.T) {
	var runCalled bool

	parent := &cobra.Command{Use: "parent"}
	addSocketFlag(parent)

	child := &cobra.Command{
		Use: "child",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			runCalled = true
			return nil
		},
	}
	parent.AddCommand(child)
	parent.SetArgs([]string{"child"})

	t.Setenv(socketEnvVar, "tcp://attacker.example/workload")
	err := parent.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), `"tcp://"`)
	assert.False(t, runCalled)
}

func TestSocketValue_RejectsTCPSchemeViaFlag(t *testing.T) {
	var runCalled bool

	parent := &cobra.Command{Use: "parent"}
	addSocketFlag(parent)

	child := &cobra.Command{
		Use: "child",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			runCalled = true
			return nil
		},
	}
	parent.AddCommand(child)
	parent.SetArgs([]string{"child", "--spiffe-endpoint-socket=tcp://attacker.example/workload"})

	err := parent.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), `"tcp://"`)
	assert.False(t, runCalled)
}
