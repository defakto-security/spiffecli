package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"time"

	"github.com/spf13/cobra"
	"github.com/defakto-security/spiffecli/internal/watch"
)

func init() {
	watchCmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch for SVID or bundle updates from the Workload API",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if socketValue(cmd) == "" {
				return errors.New("must specify flag --spiffe-endpoint-socket")
			}
			return nil
		},
	}

	addSocketFlag(watchCmd)

	rootCmd.AddCommand(watchCmd)
	watchCmd.AddCommand(NewWatchX509SVIDCmd())
	watchCmd.AddCommand(NewWatchJWTSVIDCmd())
	watchCmd.AddCommand(NewWatchBundleCmd())
}

// watchContext returns a context that is cancelled when a shutdown signal is received.
// The signals are platform-specific (see watch_signals_unix.go / watch_signals_windows.go).
func watchContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals...)
	return ctx, stop
}

// NewWatchX509SVIDCmd returns the `watch x509-svid` subcommand.
func NewWatchX509SVIDCmd() *cobra.Command {
	watcher := watch.X509SVIDWatcher{}

	cmd := &cobra.Command{
		Use:   "x509-svid",
		Short: "Stream X.509 SVID updates from the Workload API",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := watchContext()
			defer cancel()

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			watcher.WorkloadAPISocket = socket
			watcher.Output = cmd.OutOrStdout()

			if err := watcher.Watch(ctx); err != nil {
				return fmt.Errorf("watch x509-svid: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&watcher.Format, "format", watch.FormatSummaryStream,
		"Output format (json-stream, summary-stream, event-log)")

	return cmd
}

// NewWatchJWTSVIDCmd returns the `watch jwt-svid` subcommand.
func NewWatchJWTSVIDCmd() *cobra.Command {
	watcher := watch.JWTSVIDWatcher{}

	cmd := &cobra.Command{
		Use:   "jwt-svid",
		Short: "Periodically fetch and stream JWT SVID events from the Workload API",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(watcher.Audiences) == 0 {
				return fmt.Errorf("must specify --audiences")
			}

			ctx, cancel := watchContext()
			defer cancel()

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			watcher.WorkloadAPISocket = socket
			watcher.Output = cmd.OutOrStdout()

			if err := watcher.Watch(ctx); err != nil {
				return fmt.Errorf("watch jwt-svid: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&watcher.Audiences, "audiences", nil,
		"Comma-separated list of audiences for JWT SVID")
	cmd.Flags().StringVar(&watcher.Format, "format", watch.FormatSummaryStream,
		"Output format (json-stream, summary-stream, event-log)")
	cmd.Flags().DurationVar(&watcher.Interval, "interval", 60*time.Second,
		"Interval between JWT SVID fetches")

	return cmd
}

// NewWatchBundleCmd returns the `watch bundle` subcommand.
func NewWatchBundleCmd() *cobra.Command {
	watcher := watch.BundleWatcher{}

	cmd := &cobra.Command{
		Use:   "bundle TYPE",
		Short: "Stream bundle updates from the Workload API",
		Long:  "Stream bundle updates from the Workload API. TYPE must be 'x509' or 'jwt'.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s\n\n", cmd.Long)
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return fmt.Errorf("must specify bundle type (x509 or jwt)")
			}

			ctx, cancel := watchContext()
			defer cancel()

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			watcher.WorkloadAPISocket = socket
			watcher.BundleType = args[0]
			watcher.Output = cmd.OutOrStdout()

			if err := watcher.Watch(ctx); err != nil {
				return fmt.Errorf("watch bundle: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&watcher.Format, "format", watch.FormatSummaryStream,
		"Output format (json-stream, summary-stream, event-log)")

	return cmd
}
