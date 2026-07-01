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

func watchUntil(t *testing.T, w interface{ Watch(context.Context) error }, trigger string, buf *syncBuffer) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- w.Watch(ctx)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), trigger) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
		return nil
	}
}

func TestBundleWatcher_WatchX509(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := &watch.BundleWatcher{
		WorkloadAPISocket: socketAddr,
		Format:            watch.FormatJSONStream,
		BundleType:        "x509",
		Output:            &buf,
	}

	err := watchUntil(t, watcher, "bundle_updated", &buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, `"event":"bundle_updated"`)
	assert.Contains(t, output, "example.com")
}

func TestBundleWatcher_WatchJWT(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := &watch.BundleWatcher{
		WorkloadAPISocket: socketAddr,
		Format:            watch.FormatJSONStream,
		BundleType:        "jwt",
		Output:            &buf,
	}

	err := watchUntil(t, watcher, "bundle_updated", &buf)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, `"event":"bundle_updated"`)
	assert.Contains(t, output, "example.com")
}

func TestBundleWatcher_SummaryStream(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := &watch.BundleWatcher{
		WorkloadAPISocket: socketAddr,
		Format:            watch.FormatSummaryStream,
		BundleType:        "x509",
		Output:            &buf,
	}

	err := watchUntil(t, watcher, "Bundle updated", &buf)
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "Bundle updated: example.com")
}

func TestBundleWatcher_InvalidBundleType(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	watcher := watch.BundleWatcher{
		WorkloadAPISocket: socketAddr,
		Format:            watch.FormatJSONStream,
		BundleType:        "invalid",
		Output:            &bytes.Buffer{},
	}
	err := watcher.Watch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown bundle type")
}

func TestBundleWatcher_InvalidFormat(t *testing.T) {
	watcher := watch.BundleWatcher{
		WorkloadAPISocket: "unix:///nonexistent",
		Format:            "invalid-format",
		BundleType:        "x509",
		Output:            &bytes.Buffer{},
	}
	err := watcher.Watch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}
