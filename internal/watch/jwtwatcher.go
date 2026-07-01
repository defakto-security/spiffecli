package watch

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// JWTSVIDWatcher periodically fetches JWT SVIDs and emits events.
// The Workload API does not stream JWT SVIDs; this watcher re-fetches
// at a configurable interval.
type JWTSVIDWatcher struct {
	WorkloadAPISocket string
	Audiences         []string
	Format            string
	Interval          time.Duration
	Output            io.Writer
}

// Watch connects to the Workload API and periodically fetches JWT SVIDs,
// emitting events for each fetch until ctx is cancelled.
func (w *JWTSVIDWatcher) Watch(ctx context.Context) error {
	if w.Output == nil {
		w.Output = os.Stdout
	}
	if w.Format == "" {
		w.Format = FormatSummaryStream
	}
	if w.Interval <= 0 {
		w.Interval = 60 * time.Second
	}
	if len(w.Audiences) == 0 {
		return fmt.Errorf("must specify at least one audience")
	}

	formatter, err := NewFormatter(w.Format, w.Output)
	if err != nil {
		return err
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(w.WorkloadAPISocket))
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("unable to create workload API client: %w", err)
	}
	defer func() { _ = client.Close() }()

	params := jwtsvid.Params{Audience: w.Audiences[0]}
	if len(w.Audiences) > 1 {
		params.ExtraAudiences = w.Audiences[1:]
	}

	formatter.Emit(WatchEvent{Event: "watching"})

	// Fetch immediately on start.
	w.fetchAndEmit(ctx, client, params, formatter)

	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.fetchAndEmit(ctx, client, params, formatter)
		}
	}
}

func (w *JWTSVIDWatcher) fetchAndEmit(ctx context.Context, client *workloadapi.Client, params jwtsvid.Params, formatter *Formatter) {
	svid, err := client.FetchJWTSVID(ctx, params)
	if err != nil {
		if ctx.Err() == nil {
			formatter.Emit(WatchEvent{
				Event: "error",
				Error: err.Error(),
			})
		}
		return
	}
	formatter.Emit(WatchEvent{
		Event:    "jwt_svid_fetched",
		SpiffeID: svid.ID.String(),
		Expiry:   svid.Expiry.UTC().Format(time.RFC3339),
	})
}
