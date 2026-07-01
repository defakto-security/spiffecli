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

func TestJWTSVIDWatcher_Watch(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := watch.JWTSVIDWatcher{
		WorkloadAPISocket: socketAddr,
		Audiences:         []string{"test-audience"},
		Format:            watch.FormatJSONStream,
		Interval:          500 * time.Millisecond,
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
		if strings.Contains(buf.String(), "jwt_svid_fetched") {
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
	assert.Contains(t, output, `"event":"jwt_svid_fetched"`)
	assert.Contains(t, output, "spiffe://example.com")
	assert.Contains(t, output, `"expiry":`)
}

func TestJWTSVIDWatcher_MultipleAudiences(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := watch.JWTSVIDWatcher{
		WorkloadAPISocket: socketAddr,
		Audiences:         []string{"aud1", "aud2"},
		Format:            watch.FormatSummaryStream,
		Interval:          500 * time.Millisecond,
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
		if strings.Contains(buf.String(), "JWT SVID fetched") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	assert.Contains(t, buf.String(), "JWT SVID fetched")
}

func TestJWTSVIDWatcher_PeriodicRefetch(t *testing.T) {
	socketAddr := wlapitest.StartServer(t)

	var buf syncBuffer
	watcher := watch.JWTSVIDWatcher{
		WorkloadAPISocket: socketAddr,
		Audiences:         []string{"test-audience"},
		Format:            watch.FormatJSONStream,
		Interval:          100 * time.Millisecond, // fast interval to get multiple events
		Output:            &buf,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- watcher.Watch(ctx)
	}()

	// Wait until we have at least 2 jwt_svid_fetched events.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		count := strings.Count(buf.String(), "jwt_svid_fetched")
		if count >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done

	count := strings.Count(buf.String(), "jwt_svid_fetched")
	assert.GreaterOrEqual(t, count, 2, "expected at least 2 JWT SVID fetch events")
}

func TestJWTSVIDWatcher_NoAudiences(t *testing.T) {
	watcher := watch.JWTSVIDWatcher{
		WorkloadAPISocket: "unix:///nonexistent",
		Audiences:         nil,
		Format:            watch.FormatJSONStream,
		Output:            &bytes.Buffer{},
	}
	err := watcher.Watch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestJWTSVIDWatcher_InvalidFormat(t *testing.T) {
	watcher := watch.JWTSVIDWatcher{
		WorkloadAPISocket: "unix:///nonexistent",
		Audiences:         []string{"test"},
		Format:            "invalid-format",
		Output:            &bytes.Buffer{},
	}
	err := watcher.Watch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}
