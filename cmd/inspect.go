package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/defakto-security/spiffecli/internal/bundle"
	"github.com/defakto-security/spiffecli/internal/jwtinspect"
	"github.com/defakto-security/spiffecli/internal/x509inspect"
)

func init() {
	// inspectCmd represents the verify command
	inspectCmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a SPIFFE bundle, JWT, or an X.509 certificate",
	}

	rootCmd.AddCommand(inspectCmd)

	inspectCmd.AddCommand(NewInspectJWTCmd())
	inspectCmd.AddCommand(NewInspectBundleCmd())
	inspectCmd.AddCommand(NewInspectX509Cmd())
}

func NewInspectJWTCmd() *cobra.Command {
	inspector := jwtinspect.JwtInspector{}

	jwtInspectCmd := &cobra.Command{
		Use:   "jwt",
		Short: "Inspect a JWT",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := inspector.Inspect()
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), output)
			return err
		},
	}

	jwtInspectCmd.Flags().StringVar(&inspector.Filename, "filename", "", "Name of input file containing the JWT")
	jwtInspectCmd.Flags().BoolVar(&inspector.IsSvid, "isSvid", false, "Return 0 if true, 1 if false. Disables other output options")
	jwtInspectCmd.Flags().BoolVar(&inspector.OutputOptions.Header, "headers", false, "Output header information")
	jwtInspectCmd.Flags().StringVar(&inspector.OutputFormat, "format", "json", "Output format is one of \"json\", \"yaml\", or \"summary\".")
	jwtInspectCmd.Flags().BoolVar(&inspector.OutputOptions.Indent, "indent", false, "Indent JSON output. Has no effect for other output formats")
	jwtInspectCmd.Flags().BoolVar(&inspector.OutputOptions.Color, "color", false, "Enable colorized output")
	jwtInspectCmd.Flags().StringVar(&inspector.OutputOptions.TimeZone, "timezone", "", "Timezone to use for \"summary\" format. Defaults to local timezone")

	return jwtInspectCmd
}

func NewInspectX509Cmd() *cobra.Command {
	inspector := x509inspect.X509Inspector{}

	x509InspectCmd := &cobra.Command{
		Use:   "x509",
		Short: "Inspect an X.509-SVID (or any X.509 certificate)",
		Long: `Inspect an X.509-SVID or any X.509 certificate and display its fields in structured form.

Output includes all Subject Alternative Name (SAN) fields and the certificate Subject
(X.500 Distinguished Name), which may contain email addresses (PII), personal names,
and internal hostnames. Operators who pipe this command's output to external systems —
log aggregators, SIEMs, audit trails — should apply appropriate data-handling controls
before routing output to such systems.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inspector.Stderr = cmd.ErrOrStderr()
			output, err := inspector.Inspect()
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), output)
			return err
		},
	}

	x509InspectCmd.Flags().StringVar(&inspector.Filename, "filename", "", "Name of input file containing the X.509-SVID (PEM)")
	x509InspectCmd.Flags().BoolVar(&inspector.IsSvid, "isSvid", false, "Return 0 if input is a well-formed X.509-SVID, 1 otherwise. Disables other output.")
	x509InspectCmd.Flags().StringVar(&inspector.OutputFormat, "format", "json", "Output format is one of \"json\", \"yaml\", \"summary\", \"chain\", or \"tree\".")
	x509InspectCmd.Flags().BoolVar(&inspector.OutputOptions.Indent, "indent", false, "Indent JSON output. Has no effect for other output formats")
	x509InspectCmd.Flags().BoolVar(&inspector.OutputOptions.Color, "color", false, "Enable colorized output for json/yaml/summary. Has no effect for chain or tree formats.")
	x509InspectCmd.Flags().StringVar(&inspector.OutputOptions.TimeZone, "timezone", "", "Timezone to use for \"summary\" format. Defaults to local timezone")
	// Why defaults must remain zero values:
	// Inspect() in internal/x509inspect/inspector.go uses non-empty / non-false detection
	// to distinguish user-supplied flags from defaults and emit warnings when incompatible
	// with the chosen --format. Any non-zero default here causes those warnings to fire on
	// every invocation, including plain --format json. The semantic default for --tree-fields
	// ("subject") is applied inside convertCertsToTree (internal/x509inspect/tree.go).
	x509InspectCmd.Flags().StringVar(&inspector.Bundle, "bundle", "", "Path to a PEM file with additional CA certificates (for --format chain/tree).")
	x509InspectCmd.Flags().BoolVar(&inspector.ShortestPath, "shortest-path", false, "Filter chain output to the shortest valid path from leaf to a root. Requires --format chain. Roots come from --bundle or self-signed certs in --filename.")
	x509InspectCmd.Flags().StringVar(&inspector.TreeFields, "tree-fields", "", "Comma-separated per-node attributes for --format tree; if omitted, 'subject' is used. Allowed: subject, issuer, spiffe-id, serial, not-after, key-algorithm, sha256-fp.")

	return x509InspectCmd
}

func NewInspectBundleCmd() *cobra.Command {
	inspector := bundle.BundleInspector{}

	bundleInspectCmd := &cobra.Command{
		Use:   "jwks",
		Short: "Inspect a JWKS (JSON Web Key Set)",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := inspector.Inspect()
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), output)
			return err
		},
	}

	bundleInspectCmd.Flags().StringVar(&inspector.Location, "location", "", "URL or filename of bundle to inspect")
	bundleInspectCmd.Flags().StringVar(&inspector.OutputFormat, "format", "json", "Output format is one of \"json\", \"yaml\", \"summary\", or \"key-ids\".")
	bundleInspectCmd.Flags().BoolVar(&inspector.OutputOptions.Indent, "indent", false, "Indent JSON output. Has no effect for other output formats")
	bundleInspectCmd.Flags().BoolVar(&inspector.OutputOptions.Color, "color", false, "Enable colorized output")
	return bundleInspectCmd
}
