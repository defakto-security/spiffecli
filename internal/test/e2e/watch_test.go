//go:build !windows

package e2e

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runWatch starts a watch command with a context timeout and returns combined output.
// The process is killed when the context expires; the error from context
// cancellation is expected and ignored by callers.
func runWatch(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // intentional subprocess in test
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestE2E_WatchX509SVID_JSONStream(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	// Run watch for 5 seconds to capture the initial events then kill.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "x509-svid",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "json-stream",
	)

	assert.Contains(t, out, `"event":"watching"`)
	assert.Contains(t, out, `"event":"svid_updated"`)
	assert.Contains(t, out, "spiffe://example.com")
}

func TestE2E_WatchX509SVID_SummaryStream(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "x509-svid",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "summary-stream",
	)

	assert.Contains(t, out, "Watching...")
	assert.Contains(t, out, "X.509 SVID updated")
	assert.Contains(t, out, "spiffe://example.com")
}

func TestE2E_WatchX509SVID_EventLog(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "x509-svid",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "event-log",
	)

	assert.Contains(t, out, "EVENT=watching")
	assert.Contains(t, out, "EVENT=svid_updated")
}

func TestE2E_WatchBundleX509(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "bundle", "x509",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "json-stream",
	)

	assert.Contains(t, out, `"event":"bundle_updated"`)
	assert.Contains(t, out, "example.com")
}

func TestE2E_WatchBundleJWT(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "bundle", "jwt",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "json-stream",
	)

	assert.Contains(t, out, `"event":"bundle_updated"`)
	assert.Contains(t, out, "example.com")
}

func TestE2E_WatchJWTSVID(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, _ := runWatch(ctx, binary,
		"watch", "jwt-svid",
		"--spiffe-endpoint-socket", "unix://"+socketPath,
		"--format", "json-stream",
		"--audiences", "test-audience",
		"--interval", "500ms",
	)

	assert.Contains(t, out, `"event":"jwt_svid_fetched"`)
	assert.Contains(t, out, "spiffe://example.com")
}

func TestE2E_Watch_MissingSocket(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "watch", "x509-svid") //nolint:gosec // intentional subprocess in test
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify flag --spiffe-endpoint-socket")
}

func TestE2E_WatchBundle_MissingType(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)

	cmd := exec.Command(binary, "watch", "bundle", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify bundle type")
}

func TestE2E_WatchJWTSVID_MissingAudiences(t *testing.T) {
	binary := buildBinary(t)
	socketPath := newTestSocket(t)
	configPath := writeTestConfig(t, socketPath)

	startServer(t, binary, configPath)
	waitForSocket(t, socketPath, 10*time.Second)

	cmd := exec.Command(binary, "watch", "jwt-svid", //nolint:gosec // intentional subprocess in test
		"--spiffe-endpoint-socket", "unix://"+socketPath,
	)
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify --audiences")
}