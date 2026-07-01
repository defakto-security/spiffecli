package watch_test

import (
	"bytes"
	"testing"

	"github.com/defakto-security/spiffecli/internal/watch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFormatter_InvalidFormat(t *testing.T) {
	_, err := watch.NewFormatter("invalid", &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown format")
}

func TestNewFormatter_ValidFormats(t *testing.T) {
	formats := []string{watch.FormatJSONStream, watch.FormatSummaryStream, watch.FormatEventLog}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			f, err := watch.NewFormatter(format, &bytes.Buffer{})
			require.NoError(t, err)
			require.NotNil(t, f)
		})
	}
}

func TestFormatter_JSONStream(t *testing.T) {
	tests := []struct {
		name     string
		event    watch.WatchEvent
		contains []string
	}{
		{
			name: "svid_updated",
			event: watch.WatchEvent{
				Timestamp: "2024-01-01T00:00:00Z",
				Event:     "svid_updated",
				SpiffeID:  "spiffe://example.com/test",
				Expiry:    "2024-01-01T01:00:00Z",
			},
			contains: []string{`"event":"svid_updated"`, `"spiffe_id":"spiffe://example.com/test"`, `"expiry":"2024-01-01T01:00:00Z"`},
		},
		{
			name: "bundle_updated",
			event: watch.WatchEvent{
				Timestamp:   "2024-01-01T00:00:00Z",
				Event:       "bundle_updated",
				TrustDomain: "example.com",
				KeyCount:    2,
			},
			contains: []string{`"event":"bundle_updated"`, `"trust_domain":"example.com"`, `"key_count":2`},
		},
		{
			name: "error",
			event: watch.WatchEvent{
				Timestamp: "2024-01-01T00:00:00Z",
				Event:     "error",
				Error:     "connection refused",
			},
			contains: []string{`"event":"error"`, `"error":"connection refused"`},
		},
		{
			name:     "watching",
			event:    watch.WatchEvent{Timestamp: "2024-01-01T00:00:00Z", Event: "watching"},
			contains: []string{`"event":"watching"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f, err := watch.NewFormatter(watch.FormatJSONStream, &buf)
			require.NoError(t, err)
			f.Emit(tt.event)

			output := buf.String()
			for _, c := range tt.contains {
				assert.Contains(t, output, c)
			}
		})
	}
}

func TestFormatter_SummaryStream(t *testing.T) {
	tests := []struct {
		name     string
		event    watch.WatchEvent
		contains string
	}{
		{
			name: "svid_updated",
			event: watch.WatchEvent{
				Event:    "svid_updated",
				SpiffeID: "spiffe://example.com/test",
				Expiry:   "2024-01-01T01:00:00Z",
			},
			contains: "X.509 SVID updated: spiffe://example.com/test",
		},
		{
			name: "jwt_svid_fetched",
			event: watch.WatchEvent{
				Event:    "jwt_svid_fetched",
				SpiffeID: "spiffe://example.com/test",
				Expiry:   "2024-01-01T01:00:00Z",
			},
			contains: "JWT SVID fetched: spiffe://example.com/test",
		},
		{
			name: "bundle_updated",
			event: watch.WatchEvent{
				Event:       "bundle_updated",
				TrustDomain: "example.com",
				KeyCount:    2,
			},
			contains: "Bundle updated: example.com (2 keys)",
		},
		{
			name: "error",
			event: watch.WatchEvent{
				Event: "error",
				Error: "connection refused",
			},
			contains: "Error: connection refused",
		},
		{
			name:     "watching",
			event:    watch.WatchEvent{Event: "watching"},
			contains: "Watching...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f, err := watch.NewFormatter(watch.FormatSummaryStream, &buf)
			require.NoError(t, err)
			f.Emit(tt.event)
			assert.Contains(t, buf.String(), tt.contains)
		})
	}
}

func TestFormatter_EventLog(t *testing.T) {
	tests := []struct {
		name     string
		event    watch.WatchEvent
		contains string
	}{
		{
			name: "svid_updated",
			event: watch.WatchEvent{
				Timestamp: "2024-01-01T00:00:00Z",
				Event:     "svid_updated",
				SpiffeID:  "spiffe://example.com/test",
				Expiry:    "2024-01-01T01:00:00Z",
			},
			contains: `EVENT=svid_updated spiffe_id="spiffe://example.com/test"`,
		},
		{
			name: "bundle_updated",
			event: watch.WatchEvent{
				Timestamp:   "2024-01-01T00:00:00Z",
				Event:       "bundle_updated",
				TrustDomain: "example.com",
				KeyCount:    1,
			},
			contains: `EVENT=bundle_updated trust_domain="example.com" key_count=1`,
		},
		{
			name: "error",
			event: watch.WatchEvent{
				Timestamp: "2024-01-01T00:00:00Z",
				Event:     "error",
				Error:     "connection refused",
			},
			contains: `EVENT=error error="connection refused"`,
		},
		{
			name:     "watching",
			event:    watch.WatchEvent{Timestamp: "2024-01-01T00:00:00Z", Event: "watching"},
			contains: "EVENT=watching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f, err := watch.NewFormatter(watch.FormatEventLog, &buf)
			require.NoError(t, err)
			f.Emit(tt.event)
			assert.Contains(t, buf.String(), tt.contains)
		})
	}
}

func TestFormatter_AutoTimestamp(t *testing.T) {
	var buf bytes.Buffer
	f, err := watch.NewFormatter(watch.FormatJSONStream, &buf)
	require.NoError(t, err)

	f.Emit(watch.WatchEvent{Event: "watching"})

	output := buf.String()
	assert.Contains(t, output, `"timestamp":`)
	// Timestamp should not be empty.
	assert.NotContains(t, output, `"timestamp":""`)
}
