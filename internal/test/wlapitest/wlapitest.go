// Package wlapitest provides test helpers for starting a local Workload API server.
// UNIX domain sockets are used; tests skip automatically on Windows.
package wlapitest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/wlapi"
	"github.com/stretchr/testify/require"
)

// StartServer starts a test wlapi server with a single trust domain "example.com"
// and workload "spiffe://example.com/test". It returns the socket address (unix://...)
// for use with Workload API clients. The server is stopped when the test ends.
func StartServer(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("UNIX domain sockets are not supported on Windows")
	}

	// Use os.MkdirTemp with empty prefix to get a short path.
	// t.TempDir() includes the full test name which can exceed the 104-byte
	// macOS unix socket path limit for long test names.
	tmpDir, err := os.MkdirTemp("", "wlapitest")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	socketPath := filepath.Join(tmpDir, "wl.sock")

	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	id, err := spiffeid.FromString("spiffe://example.com/test")
	require.NoError(t, err)

	cfg := wlapi.Config{
		TrustDomains: []wlapi.TrustDomainConfig{
			{
				Name:             td,
				X509AuthorityTTL: 24 * time.Hour,
				JWTAuthorityTTL:  24 * time.Hour,
				Workloads: []wlapi.WorkloadConfig{
					{
						ID:               id,
						SocketPath:       socketPath,
						X509SVIDTTL:      time.Hour,
						X509SVIDRotateAt: time.Hour,
						JWTSVIDTTL:       time.Hour,
					},
				},
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = wlapi.Run(ctx, cfg)
	}()

	WaitForSocket(t, socketPath, 5*time.Second)

	return "unix://" + socketPath
}

// TrustDomain returns the spiffeid.TrustDomain used by the test server ("example.com").
func TrustDomain() spiffeid.TrustDomain {
	td, _ := spiffeid.TrustDomainFromString("example.com")
	return td
}

// WaitForSocket polls until the unix socket is ready or the timeout is exceeded.
func WaitForSocket(t *testing.T, socketPath string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for socket %s to become ready", socketPath)
}
