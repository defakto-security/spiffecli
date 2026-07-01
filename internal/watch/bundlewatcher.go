package watch

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// BundleWatcher streams bundle updates from the Workload API.
type BundleWatcher struct {
	WorkloadAPISocket string
	Format            string
	BundleType        string // "x509" or "jwt"
	Output            io.Writer
}

// Watch connects to the Workload API and emits bundle update events
// until ctx is cancelled.
func (w *BundleWatcher) Watch(ctx context.Context) error {
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

	switch w.BundleType {
	case "x509":
		watcher := &x509BundleWatcher{formatter: formatter}
		if err := client.WatchX509Bundles(ctx, watcher); err != nil && ctx.Err() == nil {
			return fmt.Errorf("X.509 bundle watch failed: %w", err)
		}
	case "jwt":
		watcher := &jwtBundleWatcher{formatter: formatter}
		if err := client.WatchJWTBundles(ctx, watcher); err != nil && ctx.Err() == nil {
			return fmt.Errorf("JWT bundle watch failed: %w", err)
		}
	default:
		return fmt.Errorf("unknown bundle type %q (valid: x509, jwt)", w.BundleType)
	}
	return nil
}

// x509BundleWatcher implements workloadapi.X509BundleWatcher.
type x509BundleWatcher struct {
	formatter *Formatter
}

func (w *x509BundleWatcher) OnX509BundlesUpdate(set *x509bundle.Set) {
	for _, bundle := range set.Bundles() {
		w.formatter.Emit(WatchEvent{
			Event:       "bundle_updated",
			TrustDomain: bundle.TrustDomain().String(),
			KeyCount:    len(bundle.X509Authorities()),
		})
	}
}

func (w *x509BundleWatcher) OnX509BundlesWatchError(err error) {
	w.formatter.Emit(WatchEvent{
		Event: "error",
		Error: err.Error(),
	})
}

// jwtBundleWatcher implements workloadapi.JWTBundleWatcher.
type jwtBundleWatcher struct {
	formatter *Formatter
}

func (w *jwtBundleWatcher) OnJWTBundlesUpdate(set *jwtbundle.Set) {
	for _, bundle := range set.Bundles() {
		w.formatter.Emit(WatchEvent{
			Event:       "bundle_updated",
			TrustDomain: bundle.TrustDomain().String(),
			KeyCount:    len(bundle.JWTAuthorities()),
		})
	}
}

func (w *jwtBundleWatcher) OnJWTBundlesWatchError(err error) {
	w.formatter.Emit(WatchEvent{
		Event: "error",
		Error: err.Error(),
	})
}
