package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	endpointSocketKey = "spiffe-endpoint-socket"
	socketEnvVar      = "SPIFFE_ENDPOINT_SOCKET"
)

// addSocketFlag registers --spiffe-endpoint-socket / -s as a persistent flag on cmd.
func addSocketFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringP(endpointSocketKey, "s", "",
		"Path to Workload API socket (env: "+socketEnvVar+")")
}

// addSocketFlagLocal registers --spiffe-endpoint-socket / -s as a non-persistent flag on cmd.
func addSocketFlagLocal(cmd *cobra.Command) {
	cmd.Flags().StringP(endpointSocketKey, "s", "",
		"Path to Workload API socket (env: "+socketEnvVar+")")
}

// socketValue returns the flag value if set, falling back to the SPIFFE_ENDPOINT_SOCKET env var.
// Callers must pass the result through ensureUnixSocketAddress to enforce the transport allow-list.
func socketValue(cmd *cobra.Command) string {
	if v, _ := cmd.Flags().GetString(endpointSocketKey); v != "" {
		return v
	}
	return os.Getenv(socketEnvVar)
}

// ensureUnixSocketAddress validates and normalizes a SPIFFE Workload API socket address.
// Only unix:// and npipe:// schemes are accepted; all others (e.g. tcp://) are rejected to
// prevent silent redirection to an unauthenticated remote endpoint.
// Bare paths are normalized to unix://<abs>. Empty input returns ("", nil).
func ensureUnixSocketAddress(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	// Allow unix:// and npipe:// (Windows named pipe) through unchanged.
	if strings.HasPrefix(path, "unix://") || strings.HasPrefix(path, "npipe://") {
		return path, nil
	}

	// Reject any other explicit scheme.
	if i := strings.Index(path, "://"); i != -1 {
		scheme := path[:i+3]
		return "", fmt.Errorf("invalid %s scheme %q: only unix:// and npipe:// are permitted", socketEnvVar, scheme)
	}

	// Bare path: normalize to unix://<abs>.
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	return "unix://" + absPath, nil
}
