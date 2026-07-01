package watch_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/test/wlapitest"
	"github.com/defakto-security/spiffecli/internal/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX509SVIDWatcher_Watch(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := watch.X509SVIDWatcher{
		WorkloadAPISocket: socketAddr,
		Format:            watch.FormatJSONStream,
		Output:            &buf,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- watcher.Watch(ctx)
	}()

	// Wait for the initial svid_updated event then cancel.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), "svid_updated") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}

	output := buf.String()
	assert.Contains(t, output, `"event":"watching"`)
	assert.Contains(t, output, `"event":"svid_updated"`)
	assert.Contains(t, output, "spiffe://example.com")
}

func TestX509SVIDWatcher_Formats(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	tests := []struct {
		format   string
		contains string
	}{
		{watch.FormatJSONStream, `"svid_updated"`},
		{watch.FormatSummaryStream, "X.509 SVID updated"},
		{watch.FormatEventLog, "EVENT=svid_updated"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf syncBuffer
			watcher := watch.X509SVIDWatcher{
				WorkloadAPISocket: socketAddr,
				Format:            tt.format,
				Output:            &buf,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				done <- watcher.Watch(ctx)
			}()

			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if strings.Contains(buf.String(), tt.contains) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			cancel()
			<-done

			assert.Contains(t, buf.String(), tt.contains)
		})
	}
}

func TestX509SVIDWatcher_InvalidFormat(t *testing.T) {
	watcher := watch.X509SVIDWatcher{
		WorkloadAPISocket: "unix:///nonexistent",
		Format:            "invalid-format",
		Output:            &bytes.Buffer{},
	}
	err := watcher.Watch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestX509SVIDWatcher_DefaultsOutput(t *testing.T) {
	// Watch with no Output set should not panic (defaults to os.Stdout).
	// We can only test the error path here without a server.
	watcher := watch.X509SVIDWatcher{
		WorkloadAPISocket: "unix:///nonexistent.sock",
		Format:            "invalid-format",
	}
	err := watcher.Watch(context.Background())
	// Returns early due to invalid format before trying to connect.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}
