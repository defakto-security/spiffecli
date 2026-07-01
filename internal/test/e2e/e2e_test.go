//go:build !windows

// Package e2e provides end-to-end tests that compile the spiffecli binary
// and test complete workflows from the user's perspective.
package e2e

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buildBinary compiles the spiffecli binary into a temp dir and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()

	binaryPath := filepath.Join(t.TempDir(), "spiffecli")

	// The test working directory is the package dir (internal/test/e2e).
	// The module root is 3 levels up.
	wd, err := os.Getwd()
	require.NoError(t, err)
	moduleRoot := filepath.Join(wd, "..", "..", "..")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".") //nolint:gosec // intentional subprocess in test
	cmd.Dir = moduleRoot
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", out)

	return binaryPath
}

// writeTestConfig writes a minimal wlapi TOML config to a temp file and returns its path.
// The config uses a custom socket path so the test controls where to connect.
func writeTestConfig(t *testing.T, socketPath string) string {
	t.Helper()

	content := `[td."example.com"]

[td."example.com".workload.frontend]
socket_path = "` + socketPath + `"
`
	configPath := filepath.Join(t.TempDir(), "dev.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0644)) //nolint:gosec // config file, 0644 is fine
	return configPath
}

// startServer starts `spiffecli run --config <configPath>` in the background
// and waits for the socket to be ready. Returns a cancel func to stop the server.
func startServer(t *testing.T, binaryPath, configPath string) context.CancelFunc {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel is used in t.Cleanup
	cmd := exec.CommandContext(ctx, binaryPath, "run", "--config", configPath) //nolint:gosec // intentional subprocess in test
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	return cancel
}

// waitForSocket polls until the unix socket is ready or the timeout is exceeded.
func waitForSocket(t *testing.T, socketPath string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s", socketPath)
}

// socketPath returns the path where wlapi puts the frontend workload socket
// when the config uses the default naming convention.
// With socket_path set explicitly we control this ourselves.
func newTestSocket(t *testing.T) string {
	t.Helper()

	// Use a short temp dir to stay within macOS UNIX_PATH_MAX (104 bytes)
	tmpDir, err := os.MkdirTemp("", "e2e")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	return filepath.Join(tmpDir, "wl.sock")
}