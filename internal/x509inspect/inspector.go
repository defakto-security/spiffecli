package x509inspect

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/defakto-security/spiffecli/internal/style"
)

// X509InspectOutputOptions holds rendering preferences only (indent, color, timezone).
// Computation inputs — bundle certs, shortest-path filtering, tree field selection —
// belong on X509ChainOptions in chain.go, not here. Adding algorithm state to this
// struct re-introduces the duplication that was removed when those fields were split out.
type X509InspectOutputOptions struct {
	Indent   bool
	Color    bool
	TimeZone string
}

// InColor implements style.OutputOptions.
func (o X509InspectOutputOptions) InColor() bool {
	return o.Color
}

// X509Inspector inspects X.509 certificates from a PEM file.
type X509Inspector struct {
	Filename      string
	Bundle        string
	IsSvid        bool
	OutputFormat  string
	ShortestPath  bool
	TreeFields    string
	OutputOptions X509InspectOutputOptions
	Stderr        io.Writer
}

// Inspect reads and formats the certificates from Filename.
func (i *X509Inspector) Inspect() (string, error) {
	if i.Filename == "" {
		return "", fmt.Errorf("must specify a file containing the X.509 certificate")
	}

	certs, err := pemutil.LoadCertificates(i.Filename)
	if err != nil {
		if errors.Is(err, pemutil.ErrNoBlocks) {
			return "", fmt.Errorf("no certificates found in file '%s'", i.Filename)
		}
		return "", fmt.Errorf("failed to read certificates from file '%s': %w", i.Filename, err)
	}

	if i.IsSvid {
		ok, reasons := checkIsSvid(certs[0])
		if !ok {
			return "", fmt.Errorf("certificate is not a well-formed X.509-SVID: %s", strings.Join(reasons, "; "))
		}
		return "", nil
	}

	// Emit warnings for incompatible flag combinations.
	//
	// Why these guards use != "":
	// Each check relies on the cobra flag default being the zero value ("", false).
	// If NewInspectX509Cmd (cmd/inspect.go) ever registers --tree-fields, --bundle,
	// or --shortest-path with a non-zero default, the corresponding warning fires on
	// every invocation that does not use that flag — including a plain
	// `inspect x509 --format json`. The semantic default for --tree-fields ("subject")
	// lives in convertCertsToTree (tree.go:33-35), not in the cobra registration, so
	// that the warning gate here can remain a reliable user-supplied-vs-default detector.
	stderr := i.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	isChainOrTree := i.OutputFormat == "chain" || i.OutputFormat == "tree"
	if i.Bundle != "" && !isChainOrTree {
		_, _ = fmt.Fprintf(stderr, "--bundle is ignored with --format %q\n", i.OutputFormat)
	}
	if i.ShortestPath && i.OutputFormat != "chain" {
		_, _ = fmt.Fprintf(stderr, "--shortest-path is ignored with --format %q\n", i.OutputFormat)
	}
	if i.TreeFields != "" && i.OutputFormat != "tree" {
		_, _ = fmt.Fprintf(stderr, "--tree-fields is ignored with --format %q\n", i.OutputFormat)
	}

	// Load bundle certs only when the format actually uses them.
	var chainOpts X509ChainOptions
	if i.Bundle != "" && isChainOrTree {
		bundleCerts, err := pemutil.LoadCertificates(i.Bundle)
		if err != nil {
			if errors.Is(err, pemutil.ErrNoBlocks) {
				return "", fmt.Errorf("no certificates found in file '%s'", i.Bundle)
			}
			return "", fmt.Errorf("failed to read certificates from file '%s': %w", i.Bundle, err)
		}
		chainOpts.BundleCerts = bundleCerts
	}

	// Parse tree fields and propagate flags to chain options.
	if i.TreeFields != "" && i.OutputFormat == "tree" {
		var fields []string
		for _, f := range strings.Split(i.TreeFields, ",") {
			if trimmed := strings.TrimSpace(f); trimmed != "" {
				fields = append(fields, trimmed)
			}
		}
		if len(fields) > 0 {
			chainOpts.TreeFields = fields
		}
	}
	chainOpts.ShortestPath = i.ShortestPath

	formatter, exists := FormatMap[i.OutputFormat]
	if !exists {
		return "", fmt.Errorf("output format %q not supported", i.OutputFormat)
	}

	convertOpts := X509ConvertOptions{Output: i.OutputOptions, Chain: chainOpts, Stderr: stderr}
	output, err := formatter.Converter(certs, convertOpts)
	if err != nil {
		if isChainOrTree {
			return "", err
		}
		return "", fmt.Errorf("error converting certificates to %s: %w", formatter.Label, err)
	}

	if i.OutputOptions.Color && formatter.Lexer != "text" {
		var b strings.Builder
		err := quick.Highlight(&b, output, formatter.Lexer, "terminal256", style.TerminalStyle)
		if err != nil {
			return "", fmt.Errorf("error colorizing output as %s: %w", formatter.Label, err)
		}
		return b.String(), nil
	}

	return output, nil
}

// checkIsSvid validates a certificate against the SPIFFE X.509-SVID spec.
// Returns (conformant, reasons); reasons lists each violated rule.
func checkIsSvid(cert *x509.Certificate) (bool, []string) {
	var reasons []string

	// §2: Exactly one URI SAN containing a valid SPIFFE ID.
	switch {
	case len(cert.URIs) == 0:
		reasons = append(reasons, "certificate has no URI SAN")
	case len(cert.URIs) > 1:
		reasons = append(reasons, "certificate has more than one URI SAN")
	default:
		_, err := spiffeid.FromURI(cert.URIs[0])
		if err != nil {
			reasons = append(reasons, "URI SAN is not a valid SPIFFE ID")
		}
	}

	// §4.1: Leaf must not be a CA; BasicConstraints extension must be present.
	if cert.IsCA {
		reasons = append(reasons, "certificate has IsCA=true (leaf certificates must not be a CA)")
	}
	if !cert.BasicConstraintsValid {
		reasons = append(reasons, "certificate does not have a valid BasicConstraints extension")
	}

	// §4.3: Key Usage must include digitalSignature.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		reasons = append(reasons, "certificate key usage does not include digitalSignature")
	}

	// §4.3: Key Usage must exclude keyCertSign and cRLSign.
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		reasons = append(reasons, "certificate key usage includes keyCertSign (not allowed for leaf SVIDs)")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		reasons = append(reasons, "certificate key usage includes cRLSign (not allowed for leaf SVIDs)")
	}

	// §4.4: Extended Key Usage, if present, must be subset of {serverAuth, clientAuth}.
	allowedEKUs := map[x509.ExtKeyUsage]bool{
		x509.ExtKeyUsageServerAuth: true,
		x509.ExtKeyUsageClientAuth: true,
	}
	for _, eku := range cert.ExtKeyUsage {
		if !allowedEKUs[eku] {
			name := extKeyUsageNames[eku]
			if name == "" {
				name = fmt.Sprintf("unknown(%d)", eku)
			}
			reasons = append(reasons, fmt.Sprintf("extended key usage contains disallowed value: %s", name))
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		reasons = append(reasons, fmt.Sprintf("extended key usage contains disallowed unknown OID: %s", asn1.ObjectIdentifier(oid).String()))
	}

	// §4.5: Validity period must be populated.
	if !cert.NotBefore.Before(cert.NotAfter) {
		reasons = append(reasons, "certificate has invalid validity period (NotBefore is not before NotAfter)")
	}

	return len(reasons) == 0, reasons
}
