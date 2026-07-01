package watch

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// X509SVIDWatcher streams X.509 SVID updates from the Workload API.
type X509SVIDWatcher struct {
	WorkloadAPISocket string
	Format            string
	Output            io.Writer
}

// Watch connects to the Workload API and emits X.509 SVID update events
// until ctx is cancelled.
func (w *X509SVIDWatcher) Watch(ctx context.Context) error {
	if w.Output == nil {
		w.Output = os.Stdout
	}
	if w.Format == "" {
		w.Format = FormatSummaryStream
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

	formatter.Emit(WatchEvent{Event: "watching"})

	watcher := &x509ContextWatcher{formatter: formatter}
	if err := client.WatchX509Context(ctx, watcher); err != nil && ctx.Err() == nil {
		return fmt.Errorf("X.509 SVID watch failed: %w", err)
	}
	return nil
}

// x509ContextWatcher implements workloadapi.X509ContextWatcher.
type x509ContextWatcher struct {
	formatter *Formatter
}

func (w *x509ContextWatcher) OnX509ContextUpdate(ctx *workloadapi.X509Context) {
	for _, svid := range ctx.SVIDs {
		expiry := ""
		if len(svid.Certificates) > 0 {
			expiry = svid.Certificates[0].NotAfter.UTC().Format(time.RFC3339)
		}
		w.formatter.Emit(WatchEvent{
			Event:    "svid_updated",
			SpiffeID: svid.ID.String(),
			Expiry:   expiry,
		})
	}
}

func (w *x509ContextWatcher) OnX509ContextWatchError(err error) {
	w.formatter.Emit(WatchEvent{
		Event: "error",
		Error: err.Error(),
	})
}
