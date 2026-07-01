package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/defakto-security/spiffecli/internal/bundle"
	identityexchange "github.com/defakto-security/spiffecli/internal/identity-exchange"
	"github.com/defakto-security/spiffecli/internal/jwtsvid"
	"github.com/defakto-security/spiffecli/internal/x509svid"
)

const (
	identityExchangeKey = "identity-exchange-token"
)

func init() {
	// getCmd represents the get command
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Request an SVID or bundle from the workload API",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if socketValue(cmd) == "" {
				return errors.New("must specify flag --spiffe-endpoint-socket")
			}

			return nil
		},
	}

	addSocketFlag(getCmd)

	check(viper.BindEnv(identityExchangeKey, "SPIFFE_IDENTITY_EXCHANGE_TOKEN"))
	getCmd.PersistentFlags().String(identityExchangeKey, "", "Identity exchange token to send on the gRPC metadata on the Workload API call")
	check(viper.BindPFlag(identityExchangeKey, getCmd.PersistentFlags().Lookup(identityExchangeKey)))
	check(getCmd.PersistentFlags().MarkHidden(identityExchangeKey))

	rootCmd.AddCommand(getCmd)

	getCmd.AddCommand(NewJWTSVIDCmd())
	getCmd.AddCommand(NewX509SVIDCmd())
	getCmd.AddCommand(NewBundleCmd())
}

func NewBundleCmd() *cobra.Command {
	client := bundle.BundleClient{}

	bundleCmd := &cobra.Command{
		Use:   "bundle FORMAT",
		Short: "Get a SPIFFE Trust Bundle",
		Long:  "Get a SPIFFE Trust Bundle in x509 or JWT format.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s\n\n", cmd.Long)
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), cmd.UsageString())
				return fmt.Errorf("must specify bundle format (jwt or x509)")
			}
			format := args[0]

			// Time out the example after 5 seconds. This prevents the example from hanging if the workload api socket does not exist.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			client.WorkloadAPISocket = socket

			switch format {
			case "jwt":
				if err := client.GetJWTBundle(ctx); err != nil {
					return fmt.Errorf("failed to get bundle: %w", err)
				}
			case "x509":
				if err := client.GetX509Bundle(ctx); err != nil {
					return fmt.Errorf("failed to get bundle: %w", err)
				}
			default:
				return fmt.Errorf("must specify valid bundle format (e.g. jwt, x509), got %s", format)
			}

			return nil
		},
	}

	bundleCmd.Flags().StringVarP(&client.TrustDomain, "trust-domain", "t", "", "The bundle's trust domain")
	bundleCmd.Flags().StringVar(&client.Filename, "filename", "", "Name of the file to output results")

	return bundleCmd
}

func NewJWTSVIDCmd() *cobra.Command {
	client := jwtsvid.JWTSVIDClient{}

	jwtsvidCmd := &cobra.Command{
		Use:   "jwt-svid",
		Short: "Get a JWT SVID",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Time out the example after 5 seconds. This prevents the example from hanging if the workload api socket does not exist.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			identityExchangeToken := viper.GetString(identityExchangeKey)
			if identityExchangeToken != "" {
				ctx = identityexchange.NewContextWithIDExchangeToken(ctx, identityExchangeToken)
			}

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			client.WorkloadAPISocket = socket

			if err := client.RequestJWTSVID(ctx); err != nil {
				return fmt.Errorf("failed to request JWT SVID: %w", err)
			}

			return nil
		},
	}

	jwtsvidCmd.Flags().BoolVarP(&client.Decode, "decode", "d", false, "Decode SVID into human-readable format")
	jwtsvidCmd.Flags().StringVar(&client.Filename, "filename", "", "Name of the file to output results")
	jwtsvidCmd.Flags().StringSliceVar(&client.Audiences, "audiences", []string{}, "Comma-separated list of audiences for JWT SVID")

	return jwtsvidCmd
}

func NewX509SVIDCmd() *cobra.Command {
	client := x509svid.X509SVIDClient{}

	x509svidCmd := &cobra.Command{
		Use:   "x509-svid",
		Short: "Get an x509 SVID",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Time out the example after 5 seconds. This prevents the example from hanging if the workload api socket does not exist.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			identityExchangeToken := viper.GetString(identityExchangeKey)
			if identityExchangeToken != "" {
				ctx = identityexchange.NewContextWithIDExchangeToken(ctx, identityExchangeToken)
			}

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			client.WorkloadAPISocket = socket

			if err := client.RequestX509SVID(ctx); err != nil {
				return fmt.Errorf("failed to request x509 SVID: %w", err)
			}

			return nil
		},
	}

	x509svidCmd.Flags().StringVar(&client.Filename, "filename", "", "Name of the file to output results")
	x509svidCmd.Flags().StringVar(&client.Format, "format", "", "Output format. Available options are pem or der")

	return x509svidCmd
}
