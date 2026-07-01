package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/defakto-security/spiffecli/internal/jwtsvid"
	"github.com/defakto-security/spiffecli/internal/x509svid"
	"github.com/defakto-security/spiffecli/internal/x509verify"
)

func init() {
	// verifyCmd represents the verify command
	verifyCmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an SVID or an X.509 certificate",
	}

	rootCmd.AddCommand(verifyCmd)

	verifyCmd.AddCommand(NewVerifyJWTSVIDCmd())
	verifyCmd.AddCommand(NewVerifyX509SVIDCmd())
	verifyCmd.AddCommand(NewVerifyX509Cmd())
}

func NewVerifyJWTSVIDCmd() *cobra.Command {
	cmd, _ := newVerifyJWTSVIDCmdWithClient()
	return cmd
}

func newVerifyJWTSVIDCmdWithClient() (*cobra.Command, *jwtsvid.JWTSVIDClient) {
	client := &jwtsvid.JWTSVIDClient{}

	jwtsvidCmd := &cobra.Command{
		Use:   "jwt-svid",
		Short: "Verify a JWT SVID",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if socketValue(cmd) == "" && client.BundleSource == "" {
				return errors.New("must specify flag --spiffe-endpoint-socket or --bundle")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Time out the example after 5 seconds. This prevents the example from hanging if the workload api socket does not exist.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// use socket when no local bundle is provided
			if client.BundleSource == "" {
				socket, err := ensureUnixSocketAddress(socketValue(cmd))
				if err != nil {
					return err
				}
				client.WorkloadAPISocket = socket
			}

			if err := client.VerifyJWTSVID(ctx); err != nil {
				return fmt.Errorf("failed to verify JWT SVID: %w", err)
			}

			return nil
		},
	}

	addSocketFlagLocal(jwtsvidCmd)

	jwtsvidCmd.Flags().StringVar(&client.Filename, "filename", "", "Name of file to read the JWT SVID from")
	jwtsvidCmd.Flags().StringVar(&client.Token, "token", "", "The JWT SVID token to verify")
	jwtsvidCmd.Flags().StringSliceVar(&client.Audiences, "audiences", []string{}, "Comma-separated list of audiences for JWT SVID")

	// Adding optional flag(s) to verify the JWT SVID against a local JWK
	jwtsvidCmd.Flags().StringVar(&client.BundleSource, "bundle", "", "URL or filename of bundle to use for verification instead of the workload API")
	jwtsvidCmd.Flags().StringVar(&client.TrustDomain, "trust-domain", "", "Trust domain to use for verification")

	return jwtsvidCmd, client
}

func NewVerifyX509SVIDCmd() *cobra.Command {
	client := x509svid.X509SVIDClient{}

	x509svidCmd := &cobra.Command{
		Use:   "x509-svid",
		Short: "Verify an x509 SVID",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if socketValue(cmd) == "" {
				return errors.New("must specify flag --spiffe-endpoint-socket")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Time out the example after 5 seconds. This prevents the example from hanging if the workload api socket does not exist.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			socket, err := ensureUnixSocketAddress(socketValue(cmd))
			if err != nil {
				return err
			}
			client.WorkloadAPISocket = socket

			if err := client.Verifyx509SVID(ctx); err != nil {
				return fmt.Errorf("failed to verify x509 SVID: %w", err)
			}

			return nil
		},
	}

	addSocketFlagLocal(x509svidCmd)

	x509svidCmd.Flags().StringVar(&client.Filename, "filename", "", "Name of the file to read the x509 SVID from")
	x509svidCmd.Flags().StringVar(&client.Format, "format", "", "Certificate format. Available options are pem or der")
	x509svidCmd.Flags().StringVar(&client.Password, "password", "", "Certificate password, for password-protected DER files")

	return x509svidCmd
}

func NewVerifyX509Cmd() *cobra.Command {

	verifier := x509verify.Verifier{}

	x509Cmd := &cobra.Command{
		Use:   "x509",
		Short: "Verify an x509 certificate against a variety of CA bundles (trust stores)",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := verifier.VerifyCertificate()
			if err != nil {
				return fmt.Errorf("certificate verification failed: %w", err)
			}
			if verifier.ShowPath {
				fmt.Println(path)
			}

			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {

			// Cobra has built-in support for flag dependencies, but their error messages aren't user-friendly
			caFlagsSet := 0
			if verifier.CaBundle != "" {
				caFlagsSet++
			}
			if verifier.SystemBundle {
				caFlagsSet++
			}
			if verifier.RootProgram != "" {
				caFlagsSet++
			}

			// At least one is required
			if caFlagsSet < 1 {
				return fmt.Errorf("must specify a CA bundle (--ca-bundle), system trust store (--system), or root program (--root-program)")
			}
			if caFlagsSet > 1 {
				return fmt.Errorf("only one of --ca-bundle, --system, or --root-program can be specified")
			}
			return nil
		},
	}
	// Certificate-related flags
	x509Cmd.Flags().StringVar(&verifier.Certificate, "certificate", "", "File or URL endpoint for certificate and chain")
	x509Cmd.Flags().StringVar(&verifier.Format, "format", "pem", "Certificate file format. Available options are 'pem' or 'der', defaults to pem")
	x509Cmd.Flags().StringVar(&verifier.Password, "password", "", "Certificate password, for password-protected DER files containing a single certificate")

	// Output flags
	x509Cmd.Flags().BoolVar(&verifier.ShowPath, "show-path", false, "Show verification path(s)")

	// Bundle-related flags
	x509Cmd.Flags().StringVar(&verifier.CaBundle, "ca-bundle", "", "Filename or URL containing list of CAs to trust. Requires --ca-format")
	x509Cmd.Flags().StringVar(&verifier.CaFormat, "ca-format", "pem", "CA bundle format. Available options are 'pem', 'jks', 'p12'")
	x509Cmd.Flags().StringVar(&verifier.CaPassword, "ca-password", "", "Password (\"integrity check\") for CA bundle, if required. Usually only necessary for Java keystores")
	x509Cmd.Flags().BoolVar(&verifier.SystemBundle, "system", false, "Use the system trust store")
	x509Cmd.Flags().StringVar(&verifier.RootProgram, "root-program", "", "Only 'mozilla' is supported")
	return x509Cmd

}
