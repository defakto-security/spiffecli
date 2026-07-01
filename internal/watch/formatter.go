package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// WatchEvent represents a single event emitted during a watch operation.
type WatchEvent struct {
	Timestamp   string `json:"timestamp"`
	Event       string `json:"event"`
	SpiffeID    string `json:"spiffe_id,omitempty"`
	Expiry      string `json:"expiry,omitempty"`
	TrustDomain string `json:"trust_domain,omitempty"`
	KeyCount    int    `json:"key_count,omitempty"`
	Error       string `json:"error,omitempty"`
}

const (
	FormatJSONStream    = "json-stream"
	FormatSummaryStream = "summary-stream"
	FormatEventLog      = "event-log"
)

// Formatter writes watch events to an output stream in the configured format.
type Formatter struct {
	format string
	out    io.Writer
	now    func() time.Time
}

// NewFormatter creates a Formatter for the given format name.
func NewFormatter(format string, out io.Writer) (*Formatter, error) {
	switch format {
	case FormatJSONStream, FormatSummaryStream, FormatEventLog:
	default:
		return nil, fmt.Errorf("unknown format %q (valid: json-stream, summary-stream, event-log)", format)
	}
	return &Formatter{format: format, out: out, now: time.Now}, nil
}

// Emit writes a single event to the output. If Timestamp is empty it is set to now.
func (f *Formatter) Emit(event WatchEvent) {
	if event.Timestamp == "" {
		event.Timestamp = f.now().UTC().Format(time.RFC3339)
	}
	switch f.format {
	case FormatJSONStream:
		data, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(f.out, "%s\n", data)
	case FormatSummaryStream:
		f.emitSummary(event)
	case FormatEventLog:
		f.emitEventLog(event)
	}
}

func (f *Formatter) emitSummary(e WatchEvent) {
	ts := e.Timestamp
	switch e.Event {
	case "svid_updated":
		_, _ = fmt.Fprintf(f.out, "[%s] X.509 SVID updated: %s (expires %s)\n", ts, e.SpiffeID, e.Expiry)
	case "jwt_svid_fetched":
		_, _ = fmt.Fprintf(f.out, "[%s] JWT SVID fetched: %s (expires %s)\n", ts, e.SpiffeID, e.Expiry)
	case "bundle_updated":
		keyWord := "keys"
		if e.KeyCount == 1 {
			keyWord = "key"
		}
		_, _ = fmt.Fprintf(f.out, "[%s] Bundle updated: %s (%d %s)\n", ts, e.TrustDomain, e.KeyCount, keyWord)
	case "error":
		_, _ = fmt.Fprintf(f.out, "[%s] Error: %s\n", ts, e.Error)
	case "watching":
		_, _ = fmt.Fprintf(f.out, "[%s] Watching...\n", ts)
	default:
		_, _ = fmt.Fprintf(f.out, "[%s] %s\n", ts, e.Event)
	}
}

func (f *Formatter) emitEventLog(e WatchEvent) {
	ts := e.Timestamp
	switch e.Event {
	case "svid_updated":
		_, _ = fmt.Fprintf(f.out, "%s EVENT=svid_updated spiffe_id=%q expiry=%q\n", ts, e.SpiffeID, e.Expiry)
	case "jwt_svid_fetched":
		_, _ = fmt.Fprintf(f.out, "%s EVENT=jwt_svid_fetched spiffe_id=%q expiry=%q\n", ts, e.SpiffeID, e.Expiry)
	case "bundle_updated":
		_, _ = fmt.Fprintf(f.out, "%s EVENT=bundle_updated trust_domain=%q key_count=%d\n", ts, e.TrustDomain, e.KeyCount)
	case "error":
		_, _ = fmt.Fprintf(f.out, "%s EVENT=error error=%q\n", ts, e.Error)
	case "watching":
		_, _ = fmt.Fprintf(f.out, "%s EVENT=watching\n", ts)
	default:
		_, _ = fmt.Fprintf(f.out, "%s EVENT=%s\n", ts, e.Event)
	}
}
