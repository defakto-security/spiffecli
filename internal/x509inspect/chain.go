package x509inspect

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
)

// X509ChainOptions holds algorithm/computation inputs that drive
// chain construction and per-node attribute extraction. These are
// distinct from X509InspectOutputOptions, which holds rendering
// preferences only.
type X509ChainOptions struct {
	BundleCerts  []*x509.Certificate
	ShortestPath bool
	TreeFields   []string
}

// X509ConvertOptions is the options bundle passed to every
// FormatMap converter. Output carries rendering preferences;
// Chain carries algorithm inputs. JSON/YAML/summary converters
// consult Output only; chain/tree converters consult both.
// Stderr is the destination for diagnostic notes emitted by chain/tree
// converters (cycle detection, alternate-path selection); nil defaults
// to os.Stderr so callers that omit it preserve today's behaviour.
type X509ConvertOptions struct {
	Output X509InspectOutputOptions
	Chain  X509ChainOptions
	Stderr io.Writer
}

// ConvertCertsToChain renders the certificate chain in root-to-leaf order,
// indented to show depth. When opts.Chain.ShortestPath is true, only the
// shortest valid path from the leaf to a root is rendered.
// Output is plain text; the chain format does not honor opts.Output.Color.
// This is enforced structurally: "chain" registers Lexer: "text" in FormatMap,
// so Inspect() skips the quick.Highlight branch (inspector.go:133).
func ConvertCertsToChain(certs []*x509.Certificate, opts X509ConvertOptions) (string, error) {
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	return convertCertsToChain(certs, opts, stderr)
}

func convertCertsToChain(certs []*x509.Certificate, opts X509ConvertOptions, stderr io.Writer) (string, error) {
	all := unionCerts(certs, opts.Chain.BundleCerts)

	if opts.Chain.ShortestPath {
		chain, err := shortestPath(all, stderr)
		if err != nil {
			return "", err
		}
		return renderChain(chain), nil
	}

	chain, err := buildChain(all)
	if err != nil {
		return "", err
	}
	return renderChain(chain), nil
}

// renderChain formats the ordered (root-to-leaf) slice of certs as indented lines.
// The SPIFFE ID bracket is appended only to the leaf (last element).
func renderChain(chain []*x509.Certificate) string {
	var sb strings.Builder
	last := len(chain) - 1
	for depth, cert := range chain {
		indent := strings.Repeat("  ", depth)
		line := indent + sanitizeForTerminal(cert.Subject.String())
		if depth == last {
			if spiffeID := extractSpiffeID(cert); spiffeID != "" {
				line += "  [" + sanitizeForTerminal(spiffeID) + "]"
			}
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// buildChain assembles a root-to-leaf ordered chain from all certs.
func buildChain(all []*x509.Certificate) ([]*x509.Certificate, error) {
	leaf, err := identifyLeaf(all)
	if err != nil {
		return nil, err
	}

	parents := buildParentMap(all)

	// Walk leaf → root.
	var chain []*x509.Certificate
	visited := map[[32]byte]bool{}
	cur := leaf
	for {
		fp := certFingerprint(cur)
		if visited[fp] {
			break
		}
		visited[fp] = true
		chain = append(chain, cur)
		parent := parents[fp]
		if parent == nil {
			break
		}
		cur = parent
	}

	// Reverse to get root-to-leaf order.
	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}
	return chain, nil
}

// shortestPath uses x509.Certificate.Verify to find the shortest valid chain.
func shortestPath(all []*x509.Certificate, stderr io.Writer) ([]*x509.Certificate, error) {
	leaf, err := identifyLeaf(all)
	if err != nil {
		return nil, err
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	foundRoot := false
	leafFP := certFingerprint(leaf)

	for _, cert := range all {
		if isSelfSigned(cert) {
			// Self-signed certs are roots regardless of whether they are the leaf.
			// This handles the case where identifyLeaf picks a self-signed cert
			// (e.g., single-cert input or a chain where the leaf is a CA).
			roots.AddCert(cert)
			foundRoot = true
		} else if certFingerprint(cert) != leafFP {
			// Non-self-signed certs are intermediates, but never the leaf itself.
			intermediates.AddCert(cert)
		}
	}

	if !foundRoot {
		return nil, fmt.Errorf("no trusted root found for --shortest-path: provide a self-signed root in --filename or --bundle")
	}

	// ExtKeyUsageAny bypasses EKU enforcement: SPIFFE SVIDs need not assert
	// serverAuth, and this is a display filter, not a trust decision.
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}

	if len(chains) > 1 {
		// Check if any alternate chain has the same length as the first.
		first := chains[0]
		altCount := 0
		for _, ch := range chains[1:] {
			if len(ch) == len(first) {
				altCount++
			}
		}
		if altCount > 0 {
			if altCount == 1 {
				_, _ = fmt.Fprintf(stderr, "note: 1 alternate path of equal length exists; selected the first\n")
			} else {
				_, _ = fmt.Fprintf(stderr, "note: %d alternate paths of equal length exist; selected the first\n", altCount)
			}
		}
	}

	// chains[0] is leaf-to-root; reverse to root-to-leaf.
	chain := chains[0]
	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}
	return chain, nil
}

// identifyLeaf finds the leaf certificate in the union.
// Prefers a cert with a valid SPIFFE ID URI SAN; falls back to the cert that
// no other cert claims as a child (by AKI/SKI or issuer/subject DN).
func identifyLeaf(all []*x509.Certificate) (*x509.Certificate, error) {
	// Prefer SPIFFE leaf.
	for _, cert := range all {
		if extractSpiffeID(cert) != "" && !cert.IsCA {
			return cert, nil
		}
	}

	// Pre-compute fingerprints once to avoid repeated SHA-256 calls in the O(n²) loop.
	fps := make([][32]byte, len(all))
	for i, cert := range all {
		fps[i] = certFingerprint(cert)
	}

	// Build set of fingerprints that are claimed as parents.
	parentFPs := map[[32]byte]bool{}
	for i, cert := range all {
		for j, parent := range all {
			if i == j {
				continue
			}
			if isParent(cert, parent) {
				parentFPs[fps[j]] = true
			}
		}
	}

	// Leaf = the cert not claimed as a parent.
	var leaves []*x509.Certificate
	for i, cert := range all {
		if !parentFPs[fps[i]] {
			leaves = append(leaves, cert)
		}
	}
	if len(leaves) == 1 {
		return leaves[0], nil
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("no leaf certificate found (all certs appear to be intermediate/root CAs)")
	}
	// Multiple unclaimed certs: pick the non-CA one, or the first.
	for _, c := range leaves {
		if !c.IsCA {
			return c, nil
		}
	}
	return leaves[0], nil
}

// buildParentMap returns a map from cert fingerprint → its parent cert.
func buildParentMap(all []*x509.Certificate) map[[32]byte]*x509.Certificate {
	// Pre-compute fingerprints once to avoid repeated SHA-256 calls in the O(n²) loop.
	fps := make([][32]byte, len(all))
	for i, cert := range all {
		fps[i] = certFingerprint(cert)
	}

	m := map[[32]byte]*x509.Certificate{}
	for i, cert := range all {
		for j, parent := range all {
			if i == j {
				continue
			}
			if isParent(cert, parent) {
				m[fps[i]] = parent
				break
			}
		}
	}
	return m
}

// isParent returns true if parent is the direct issuer of cert.
// Callers must guarantee cert != parent (by index or pointer) before calling.
func isParent(cert, parent *x509.Certificate) bool {
	// Primary: when both AKI and SKI are present, use them exclusively.
	if len(cert.AuthorityKeyId) > 0 && len(parent.SubjectKeyId) > 0 {
		return bytes.Equal(cert.AuthorityKeyId, parent.SubjectKeyId) &&
			bytes.Equal(cert.RawIssuer, parent.RawSubject)
	}
	// Fallback: DN match plus signature verification. AKI or SKI is absent so we
	// cannot rely on key-id matching alone. During CA rotation, multiple candidate
	// parents can share the same Subject DN but different signing keys; a pure DN
	// match would mis-link the child to a same-DN sibling that did not sign it.
	// CheckSignatureFrom disambiguates by verifying the cryptographic signature.
	return bytes.Equal(cert.RawIssuer, parent.RawSubject) &&
		cert.CheckSignatureFrom(parent) == nil
}

// isSelfSigned returns true if the cert is genuinely self-signed: the issuer
// DN equals the subject DN and the certificate's signature verifies against
// its own public key. A self-issued cert whose signature was made by a
// different key (e.g. a cross-signed CA) returns false.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// unionCerts returns a deduplicated union of a and b by fingerprint.
func unionCerts(a, b []*x509.Certificate) []*x509.Certificate {
	seen := map[[32]byte]bool{}
	var result []*x509.Certificate
	for _, c := range append(a, b...) {
		fp := certFingerprint(c)
		if !seen[fp] {
			seen[fp] = true
			result = append(result, c)
		}
	}
	return result
}

// certFingerprint returns a stable map key for a certificate as a [32]byte
// SHA-256 digest of the raw DER bytes. The array is comparable and usable
// as a map key without any heap allocation.
func certFingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}
