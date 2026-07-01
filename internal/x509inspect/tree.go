package x509inspect

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/list"
)

// allowedTreeFields is the set of valid --tree-fields values.
var allowedTreeFields = []string{
	"subject", "issuer", "spiffe-id", "serial", "not-after", "key-algorithm", "sha256-fp",
}

// ConvertCertsToTree renders the certificate forest as a Unicode tree.
// Output is plain text; the tree format does not honor opts.Output.Color.
// This is enforced structurally: "tree" registers Lexer: "text" in FormatMap,
// so Inspect() skips the quick.Highlight branch (inspector.go:133).
func ConvertCertsToTree(certs []*x509.Certificate, opts X509ConvertOptions) (string, error) {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	return convertCertsToTree(certs, opts, stderr)
}

func convertCertsToTree(certs []*x509.Certificate, opts X509ConvertOptions, stderr io.Writer) (string, error) {
	fields := opts.Chain.TreeFields
	// Safety net for non-cobra callers that omit TreeFields.
	if len(fields) == 0 {
		fields = []string{"subject"}
	}

	for _, f := range fields {
		if !isAllowedTreeField(f) {
			return "", fmt.Errorf("unknown tree field '%s'; allowed: %s", sanitizeForTerminal(f), strings.Join(allowedTreeFields, ", "))
		}
	}

	all := unionCerts(certs, opts.Chain.BundleCerts)
	parents := buildParentMap(all)

	// Pre-compute fingerprints once to avoid repeated SHA-256 calls in the
	// children-map and roots-collection loops.
	fps := make([][32]byte, len(all))
	fpByPtr := make(map[*x509.Certificate][32]byte, len(all))
	for i, cert := range all {
		fps[i] = certFingerprint(cert)
		fpByPtr[cert] = fps[i]
	}

	// Find children map (inverse of parents).
	children := map[[32]byte][]*x509.Certificate{}
	for i, cert := range all {
		fp := fps[i]
		parent := parents[fp]
		if parent != nil {
			pfp := fpByPtr[parent]
			children[pfp] = append(children[pfp], cert)
		}
	}

	// Roots = certs with no parent in the union.
	var roots []*x509.Certificate
	for i, cert := range all {
		if parents[fps[i]] == nil {
			roots = append(roots, cert)
		}
	}
	// Fallback: every cert claims a parent (orphaned cycle). Pick the first cert
	// as a synthetic root so writeTreeNode is entered and the visited-set cycle
	// guard can fire.
	if len(all) > 0 && len(roots) == 0 {
		synth := all[0]
		fp256 := sha256.Sum256(synth.Raw)
		// Use serial+sha256 instead of subject DN: subject content in malformed or
		// attacker-supplied bundles may contain control characters or sensitive data.
		_, _ = fmt.Fprintf(stderr, "no root found: starting traversal from serial=%s sha256=%x to trigger cycle detection\n",
			sanitizeForTerminal(synth.SerialNumber.Text(16)), fp256)
		roots = []*x509.Certificate{synth}
	}

	var sb strings.Builder
	for i, root := range roots {
		if i > 0 {
			sb.WriteByte('\n')
		}
		visited := map[[32]byte]bool{}
		l := list.NewWriter()
		l.SetStyle(list.StyleConnectedLight)
		writeTreeNode(l, root, children, fpByPtr, fields, visited, stderr)
		sb.WriteString(l.Render())
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func writeTreeNode(
	l list.Writer,
	cert *x509.Certificate,
	children map[[32]byte][]*x509.Certificate,
	fpByPtr map[*x509.Certificate][32]byte,
	fields []string,
	visited map[[32]byte]bool,
	stderr io.Writer,
) {
	fp := fpByPtr[cert]
	if visited[fp] {
		// Same rationale as the "no root found" note above: emit serial+sha256, not subject DN.
		_, _ = fmt.Fprintf(stderr, "cycle: serial=%s sha256=%x revisited\n", sanitizeForTerminal(cert.SerialNumber.Text(16)), fp)
		return
	}
	visited[fp] = true

	// Build the node label: first field as main item, remaining as continuation lines.
	lines := nodeLines(cert, fields)
	if len(lines) == 0 {
		lines = []string{sanitizeForTerminal(cert.Subject.String())}
	}

	l.AppendItem(strings.Join(lines, "\n"))
	l.Indent()

	for _, child := range children[fp] {
		writeTreeNode(l, child, children, fpByPtr, fields, visited, stderr)
	}
	l.UnIndent()
}

// nodeLines returns one string per requested field for a certificate node.
func nodeLines(cert *x509.Certificate, fields []string) []string {
	lines := make([]string, 0, len(fields))
	for i, field := range fields {
		val := treeFieldValue(cert, field)
		if i == 0 {
			lines = append(lines, val)
		} else {
			lines = append(lines, field+": "+val)
		}
	}
	return lines
}

// treeFieldValue returns the rendered value for a given field name.
func treeFieldValue(cert *x509.Certificate, field string) string {
	switch field {
	case "subject":
		return sanitizeForTerminal(cert.Subject.String())
	case "issuer":
		return sanitizeForTerminal(cert.Issuer.String())
	case "spiffe-id":
		if id := extractSpiffeID(cert); id != "" {
			return sanitizeForTerminal(id)
		}
		return "(none)"
	case "serial":
		return cert.SerialNumber.Text(16)
	case "not-after":
		return cert.NotAfter.UTC().Format(time.RFC3339)
	case "key-algorithm":
		return keyAlgorithmString(cert)
	case "sha256-fp":
		return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	default:
		return ""
	}
}

func isAllowedTreeField(f string) bool {
	for _, allowed := range allowedTreeFields {
		if f == allowed {
			return true
		}
	}
	return false
}
