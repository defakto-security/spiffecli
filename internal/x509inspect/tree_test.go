package x509inspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertCertsToTree_SingleRoot(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root, intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.NotEmpty(t, out)
	// Root subject must appear.
	assert.Contains(t, out, "Root CA")
	// Leaf subject must appear.
	assert.Contains(t, out, "workload")
	// Tree connectors from go-pretty (StyleConnectedLight uses └─).
	assert.Contains(t, out, "└─")
}

func TestConvertCertsToTree_MultiRootForest(t *testing.T) {
	root1, _, leaf1 := testx509.NewThreeLevelSPIFFEChain(t)
	// Second independent root + leaf (no intermediate).
	root2CA := newCAAndLeafSVID_helper(t, "spiffe://other.com/svc")
	root2 := root2CA[0]
	leaf2 := root2CA[1]

	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root1, leaf1, root2, leaf2}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	// Forest: two subtrees separated by a blank line.
	parts := strings.Split(strings.TrimRight(out, "\n"), "\n\n")
	assert.GreaterOrEqual(t, len(parts), 2, "forest should have at least 2 subtrees")
}

// newCAAndLeafSVID_helper returns [caCert, leafCert] for a minimal 2-cert chain.
func newCAAndLeafSVID_helper(t *testing.T, spiffeID string) []*x509.Certificate {
	t.Helper()
	ca, leaf, _ := newCAAndLeafSVID(t, spiffeID)
	return []*x509.Certificate{ca, leaf}
}

func TestConvertCertsToTree_DefaultFieldsOneLinePerNode(t *testing.T) {
	root, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	// No field-label lines (continuation lines like "not-after: ..." should be absent).
	assert.NotContains(t, out, "not-after:")
	assert.NotContains(t, out, "issuer:")
}

func TestConvertCertsToTree_MultipleFields(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "not-after", "serial"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root, intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "not-after:")
	assert.Contains(t, out, "serial:")
}

func TestConvertCertsToTree_AllAllowedFields(t *testing.T) {
	_, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{
		TreeFields: []string{"subject", "issuer", "spiffe-id", "serial", "not-after", "key-algorithm", "sha256-fp"},
	}}
	out, err := convertCertsToTree([]*x509.Certificate{leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "issuer:")
	assert.Contains(t, out, "spiffe-id:")
	assert.Contains(t, out, "serial:")
	assert.Contains(t, out, "not-after:")
	assert.Contains(t, out, "key-algorithm: ECDSA P-256")
	assert.Contains(t, out, "sha256-fp:")
}

func TestConvertCertsToTree_UnknownField(t *testing.T) {
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"foo"}}}
	_, err := convertCertsToTree([]*x509.Certificate{root}, opts, &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown tree field 'foo'")
	assert.Contains(t, err.Error(), "subject, issuer, spiffe-id, serial, not-after, key-algorithm, sha256-fp")
}

// TestConvertCertsToTree_UnknownFieldErrorDerivedFromAllowedTreeFields verifies that
// the unknown-field error message lists exactly the values in allowedTreeFields, in
// order, so that the error stays in sync if the slice grows.
func TestConvertCertsToTree_UnknownFieldErrorDerivedFromAllowedTreeFields(t *testing.T) {
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"bogus"}}}
	_, err := convertCertsToTree([]*x509.Certificate{root}, opts, &bytes.Buffer{})
	require.Error(t, err)
	msg := err.Error()
	for _, field := range allowedTreeFields {
		assert.Contains(t, msg, field, "error message must list allowed field %q", field)
	}
	// Verify the fields appear in the same order as allowedTreeFields.
	joined := strings.Join(allowedTreeFields, ", ")
	assert.Contains(t, msg, joined, "error message must list allowed fields in allowedTreeFields order")
}

func TestConvertCertsToTree_CycleDetection(t *testing.T) {
	// Use two CA intermediates so both have non-empty SubjectKeyId.
	// The primary AKI/SKI branch in isParent then creates the mutual cycle without
	// requiring signature verification (which the fallback branch now enforces).
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int1Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 1"}),
	)
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int2Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 2"}),
	)

	// Build two certs with mutually-referencing Issuer/Subject/AKI/SKI fields so
	// that buildParentMap assigns each as the other's parent. Neither will appear
	// in roots (every cert has a parent), triggering the orphaned-cycle fallback
	// in convertCertsToTree, which picks all[0] as a synthetic root and starts
	// traversal — the visited-set guard then fires deterministically.
	a := *int1
	b := *int2
	// Make a claim b as parent: a.AKI = b.SKI, a.RawIssuer = b.RawSubject
	a.AuthorityKeyId = b.SubjectKeyId
	a.RawIssuer = b.RawSubject
	// Make b claim a as parent: b.AKI = a.SKI, b.RawIssuer = a.RawSubject
	b.AuthorityKeyId = a.SubjectKeyId
	b.RawIssuer = a.RawSubject

	var stderr bytes.Buffer
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{&a, &b}, opts, &stderr)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
	stderrStr := stderr.String()
	assert.Contains(t, stderrStr, "no root found")
	assert.Contains(t, stderrStr, "cycle:")
	assert.Contains(t, stderrStr, "serial=")
	assert.Contains(t, stderrStr, "sha256=")
	assert.Contains(t, stderrStr, "revisited")
}

// TestConvertCertsToTree_EmptyInput verifies that nil or empty cert slices
// return an empty string without panicking.
func TestConvertCertsToTree_EmptyInput(t *testing.T) {
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}

	out, err := convertCertsToTree(nil, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Empty(t, out)

	out, err = convertCertsToTree([]*x509.Certificate{}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Empty(t, out)
}

// TestConvertCertsToTree_CycleDetection_ThreeCerts verifies that the orphaned-cycle
// fallback and visited-set guard work for a 3-cert mutual cycle (A→B→C→A).
func TestConvertCertsToTree_CycleDetection_ThreeCerts(t *testing.T) {
	// Use three CA certs so all have non-empty SubjectKeyId, enabling the
	// primary AKI/SKI branch in isParent to build the cycle.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int1Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 1"}),
	)
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int2Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 2"}),
	)

	a := *root
	b := *int1
	c := *int2

	// a claims b as parent
	a.AuthorityKeyId = b.SubjectKeyId
	a.RawIssuer = b.RawSubject
	// b claims c as parent
	b.AuthorityKeyId = c.SubjectKeyId
	b.RawIssuer = c.RawSubject
	// c claims a as parent
	c.AuthorityKeyId = a.SubjectKeyId
	c.RawIssuer = a.RawSubject

	var stderr bytes.Buffer
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{&a, &b, &c}, opts, &stderr)
	require.NoError(t, err)
	assert.NotEmpty(t, out)
	stderrStr := stderr.String()
	assert.Contains(t, stderrStr, "no root found")
	assert.Contains(t, stderrStr, "cycle:")
	assert.Contains(t, stderrStr, "serial=")
	assert.Contains(t, stderrStr, "sha256=")
	assert.Contains(t, stderrStr, "revisited")
}

// TestConvertCertsToTree_OrphanedCycleFallback_StderrNote verifies that the
// fallback note is emitted exactly once, carries serial= and sha256= identifiers,
// and does not include the subject DN of any cycle cert.
func TestConvertCertsToTree_OrphanedCycleFallback_StderrNote(t *testing.T) {
	// Use two CA intermediates so both have non-empty SubjectKeyId, enabling
	// the primary AKI/SKI branch in isParent to build the mutual cycle.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int1Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 1"}),
	)
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int2Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 2"}),
	)

	a := *int1
	b := *int2
	a.AuthorityKeyId = b.SubjectKeyId
	a.RawIssuer = b.RawSubject
	b.AuthorityKeyId = a.SubjectKeyId
	b.RawIssuer = a.RawSubject

	var stderr bytes.Buffer
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	var treeErr error
	_, treeErr = convertCertsToTree([]*x509.Certificate{&a, &b}, opts, &stderr)
	require.NoError(t, treeErr)

	stderrStr := stderr.String()
	lines := strings.Split(strings.TrimRight(stderrStr, "\n"), "\n")

	// Exactly one "no root found" line.
	var noRootLines []string
	for _, l := range lines {
		if strings.Contains(l, "no root found") {
			noRootLines = append(noRootLines, l)
		}
	}
	require.Len(t, noRootLines, 1, "expected exactly one 'no root found' line in stderr")

	noRootLine := noRootLines[0]
	assert.Contains(t, noRootLine, "serial=")
	assert.Contains(t, noRootLine, "sha256=")
	// Must not contain the subject DN of the synthetic root cert.
	assert.NotContains(t, noRootLine, a.Subject.String())
}

// TestConvertCertsToTree_HealthyInput_StderrEmpty verifies that rendering a
// valid (non-cyclic) certificate produces no stderr output.
func TestConvertCertsToTree_HealthyInput_StderrEmpty(t *testing.T) {
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	var stderr bytes.Buffer
	_, err := convertCertsToTree([]*x509.Certificate{root}, opts, &stderr)
	require.NoError(t, err)
	assert.Empty(t, stderr.String(), "stderr must be empty for healthy (non-cyclic) input")
}

func TestConvertCertsToTree_SpiffeIDField(t *testing.T) {
	_, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "spiffe-id"}}}
	out, err := convertCertsToTree([]*x509.Certificate{leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "spiffe-id: spiffe://example.com/workload")
}

func TestConvertCertsToTree_SpiffeIDField_NoneWhenNoSpiffeID(t *testing.T) {
	// A CA cert has no SPIFFE ID — spiffe-id field should render "(none)".
	rootCA := newCAAndLeafSVID_helper(t, "spiffe://skip.example.com/unused")
	caCert := rootCA[0]
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "spiffe-id"}}}
	out, err := convertCertsToTree([]*x509.Certificate{caCert}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "spiffe-id: (none)")
}

func TestConvertCertsToTree_EmptyTreeFieldsDefaultsToSubject(t *testing.T) {
	// When TreeFields is nil, convertCertsToTree defaults to ["subject"].
	root, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{} // TreeFields nil
	out, err := convertCertsToTree([]*x509.Certificate{root, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "workload")
	assert.NotContains(t, out, "not-after:")
}

func TestConvertCertsToTree_BundleCertsExtendsTree(t *testing.T) {
	// Root in BundleCerts; intermediate + leaf in certs. Tree should show all three.
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{
		TreeFields:  []string{"subject"},
		BundleCerts: []*x509.Certificate{root},
	}}
	out, err := convertCertsToTree([]*x509.Certificate{intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "Intermediate CA")
	assert.Contains(t, out, "workload")
}

func TestConvertCertsToTree_SingleCert(t *testing.T) {
	// A single self-signed root renders as a single top-level node.
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "Root CA")
	assert.NotContains(t, out, "└─", "a single root with no children must not have tree connectors")
}

// TestConvertCertsToTree_SanitizesControlCharacters builds a cert whose Subject CN
// contains an ANSI escape sequence and a BEL byte, then renders it with
// --tree-fields subject,issuer,spiffe-id and asserts no raw C0/C1/DEL bytes
// from the cert payload reach the output.
func TestConvertCertsToTree_SanitizesControlCharacters(t *testing.T) {
	rootKey, rootKeyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, rootKeyErr)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(88),
		Subject:               pkix.Name{CommonName: "\x1b[31mEvil", Organization: []string{"\x07beep"}},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "issuer", "spiffe-id"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)

	// No C0 (except structural \n/\t), DEL, or C1 rune must appear in the output.
	// Iterate over runes (not bytes) so UTF-8 continuation bytes of box-drawing
	// characters (e.g. U+2514 └) are not misidentified as C1 control chars.
	for byteOff, r := range out {
		if r == '\n' || r == '\t' {
			continue
		}
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			t.Errorf("output rune at byte offset %d is a control character: U+%04X", byteOff, r)
		}
	}
	// The U+FFFD replacement character must appear in the output.
	assert.Contains(t, out, "�", "output must contain U+FFFD in place of control chars")
}

// TestWriteTreeNode_CycleEmitsNonPIIMessage verifies that the cycle-detection
// stderr message contains serial= and sha256= identifiers, not the subject DN.
func TestWriteTreeNode_CycleEmitsNonPIIMessage(t *testing.T) {
	root, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	// Build a children map that creates an artificial cycle:
	// root → leaf → root (leaf "points back" to root).
	children := map[[32]byte][]*x509.Certificate{
		certFingerprint(root): {leaf},
		certFingerprint(leaf): {root},
	}
	visited := map[[32]byte]bool{}

	var stderr bytes.Buffer
	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedLight)

	fpByPtr := map[*x509.Certificate][32]byte{
		root: certFingerprint(root),
		leaf: certFingerprint(leaf),
	}

	// Traverse starting from root. Sequence: visit root, visit leaf, then try to
	// visit root again — visited set fires cycle detection and writes to stderr.
	writeTreeNode(l, root, children, fpByPtr, []string{"subject"}, visited, &stderr)

	stderrStr := stderr.String()
	// Must contain non-PII identifiers.
	assert.Contains(t, stderrStr, "serial=")
	assert.Contains(t, stderrStr, "sha256=")
	// Must NOT contain the subject DN of the cert caught in the cycle.
	assert.NotContains(t, stderrStr, root.Subject.CommonName)
}

// TestTreeFieldValue_SanitizesIssuerField verifies that treeFieldValue sanitizes
// the "issuer" field when the issuer's subject DN contains control characters.
// An attacker-supplied --bundle cert with a malicious Subject CN would cause
// leaf certs signed by it to have a malicious Issuer DN.
func TestTreeFieldValue_SanitizesIssuerField(t *testing.T) {
	maliciousRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Root CA with a control character in its subject CN — becomes the issuer DN of leaf certs.
	maliciousRootCA := testx509.NewCertificateAuthority(t, "\x1b[31mEvil Root", testx509.WithSigner(maliciousRootKey))
	leaf := maliciousRootCA.GenerateLeafCertificate(t)

	val := treeFieldValue(leaf, "issuer")
	assert.NotContains(t, val, "\x1b", "issuer field must not contain ESC byte")
	assert.Contains(t, val, "�", "issuer field must contain U+FFFD in place of ESC byte")
}

// TestConvertCertsToTree_FingerprintPrecomputeOrdering verifies that the
// pre-computed fpByPtr lookup is order-invariant: when BundleCerts supplies
// [leaf, intermediate, root] (children before parents in the union), the
// parent-child relationships are still resolved correctly. This exercises the
// fpByPtr[parent] map rather than a naive certFingerprint(parent) call, which
// would produce the same result but validates the new code path introduced in
// the pre-computation refactor.
func TestConvertCertsToTree_FingerprintPrecomputeOrdering(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	// Pass everything as BundleCerts in leaf-first order so the union is
	// [leaf, intermediate, root] — parents appear at higher indices than
	// their children. fpByPtr must resolve parent fingerprints correctly
	// regardless of index.
	opts := X509ConvertOptions{Chain: X509ChainOptions{
		TreeFields:  []string{"subject"},
		BundleCerts: []*x509.Certificate{leaf, intermediate, root},
	}}
	out, err := convertCertsToTree(nil, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "Intermediate CA")
	assert.Contains(t, out, "workload")
	// Tree connectors indicate the children map was built correctly.
	assert.Contains(t, out, "└─")
}

// BenchmarkConvertCertsToTree_FingerprintPrecompute documents the fingerprint
// pre-computation refactor: within the map-building loops (children-map
// construction) and the writeTreeNode traversal, certFingerprint is called at
// most once per certificate — the pre-computation pass hashes each cert once
// and the loops reuse fps[i] / fpByPtr[parent] without rehashing.
//
// Two paths outside that guarantee intentionally re-hash on their own:
//   - The orphaned-cycle fallback (tree.go:80) calls sha256.Sum256 directly
//     on the synthetic root to produce a non-PII cycle note.
//   - The "sha256-fp" tree field (tree.go:168) calls sha256.Sum256 per node
//     when that field is requested at render time.
func BenchmarkConvertCertsToTree_FingerprintPrecompute(b *testing.B) {
	const N = 50
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	allCerts := make([]*x509.Certificate, N)
	for i := range allCerts {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: fmt.Sprintf("cert-%d", i)},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		raw, certErr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if certErr != nil {
			b.Fatal(certErr)
		}
		cert, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			b.Fatal(parseErr)
		}
		allCerts[i] = cert
	}
	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}}
	var stderr bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stderr.Reset()
		if _, benchErr := convertCertsToTree(allCerts, opts, &stderr); benchErr != nil {
			b.Fatal(benchErr)
		}
	}
}

// TestConvertCertsToTree_CycleNote_RoutedToOptsStderr verifies that the
// "no root found" diagnostic emitted by the tree converter (orphaned-cycle
// fallback) is written to opts.Stderr when set, not to os.Stderr.
func TestConvertCertsToTree_CycleNote_RoutedToOptsStderr(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int1Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Cycle CA 1"}),
	)
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int2Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Cycle CA 2"}),
	)

	// Swap AKI/RawIssuer to create a mutual cycle (neither has a root).
	a := *int1
	b := *int2
	a.AuthorityKeyId = b.SubjectKeyId
	a.RawIssuer = b.RawSubject
	b.AuthorityKeyId = a.SubjectKeyId
	b.RawIssuer = a.RawSubject

	var stderrBuf bytes.Buffer
	opts := X509ConvertOptions{
		Chain:  X509ChainOptions{TreeFields: []string{"subject"}},
		Stderr: &stderrBuf,
	}
	_, err = ConvertCertsToTree([]*x509.Certificate{&a, &b}, opts)
	require.NoError(t, err)
	assert.Contains(t, stderrBuf.String(), "no root found",
		"cycle fallback note must be routed to opts.Stderr, not os.Stderr")
}

// TestConvertCertsToTree_WriteTreeNodeCycleRevisit_RoutedToOptsStderr verifies that
// the "cycle: serial=... sha256=... revisited" diagnostic emitted by writeTreeNode
// is written to opts.Stderr, not to os.Stderr. This is distinct from the "no root
// found" fallback note: it fires when writeTreeNode encounters a cert whose
// fingerprint is already in the visited set during tree traversal.
func TestConvertCertsToTree_WriteTreeNodeCycleRevisit_RoutedToOptsStderr(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	int1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int1Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Revisit Node 1"}),
	)
	int2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(int2Key.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Revisit Node 2"}),
	)

	// Swap AKI/RawIssuer to create a mutual cycle: a claims b as parent, b claims
	// a as parent. buildParentMap assigns children[fp_a]=[b] and children[fp_b]=[a].
	// When convertCertsToTree picks the synthetic root (all[0]=a) and calls
	// writeTreeNode, it visits a then b then tries to revisit a — triggering the
	// "cycle: serial=... sha256=... revisited" emit.
	a := *int1
	b := *int2
	a.AuthorityKeyId = b.SubjectKeyId
	a.RawIssuer = b.RawSubject
	b.AuthorityKeyId = a.SubjectKeyId
	b.RawIssuer = a.RawSubject

	var stderrBuf bytes.Buffer
	opts := X509ConvertOptions{
		Chain:  X509ChainOptions{TreeFields: []string{"subject"}},
		Stderr: &stderrBuf,
	}
	_, err = ConvertCertsToTree([]*x509.Certificate{&a, &b}, opts)
	require.NoError(t, err)

	diagnostic := stderrBuf.String()
	assert.Contains(t, diagnostic, "cycle:",
		"writeTreeNode cycle-revisit note must be routed to opts.Stderr, not os.Stderr")
	assert.Contains(t, diagnostic, "revisited",
		"writeTreeNode cycle-revisit note must be routed to opts.Stderr, not os.Stderr")
	assert.Contains(t, diagnostic, "serial=",
		"cycle note must contain the hex serial identifier, not the subject DN")
	assert.Contains(t, diagnostic, "sha256=",
		"cycle note must contain the SHA-256 fingerprint identifier")
}

// TestWriteTreeNode_CycleWarning_SHA256MatchesCertRaw verifies that the sha256= value
// emitted in the cycle warning equals sha256.Sum256(cert.Raw) for the revisited cert.
// This is the direct correctness check for the refactor that replaced a per-call
// sha256.Sum256(cert.Raw) with the pre-computed fpByPtr[cert]: both must produce
// identical bytes.
func TestWriteTreeNode_CycleWarning_SHA256MatchesCertRaw(t *testing.T) {
	root, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	// children[root] = [leaf], children[leaf] = [root] — traversing root→leaf→root
	// triggers cycle detection when writeTreeNode tries to revisit root.
	children := map[[32]byte][]*x509.Certificate{
		certFingerprint(root): {leaf},
		certFingerprint(leaf): {root},
	}
	visited := map[[32]byte]bool{}

	fpByPtr := map[*x509.Certificate][32]byte{
		root: certFingerprint(root),
		leaf: certFingerprint(leaf),
	}

	var stderr bytes.Buffer
	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedLight)
	writeTreeNode(l, root, children, fpByPtr, []string{"subject"}, visited, &stderr)

	stderrStr := stderr.String()
	require.Contains(t, stderrStr, "sha256=")

	// The sha256= in the warning must equal sha256.Sum256(root.Raw) exactly.
	expectedHex := fmt.Sprintf("%x", sha256.Sum256(root.Raw))
	assert.Contains(t, stderrStr, "sha256="+expectedHex,
		"cycle warning sha256= must equal sha256.Sum256(cert.Raw) for the revisited cert")
	// Sanity-check the fingerprint is non-zero (catches a zero-map-value regression).
	assert.NotEqual(t, strings.Repeat("0", 64), expectedHex)
}

// TestConvertCertsToTree_SpiffeIDFieldSafeWithMaliciousURISAN builds a cert with a URI
// SAN whose path contains a raw control character. After the x509 DER round-trip the
// path is percent-encoded, and the SPIFFE library's strict path validator rejects the
// percent sign, so extractSpiffeID returns "" and the field shows "(none)". The test
// verifies that no C0/C1/DEL bytes from the cert payload reach the rendered output.
func TestConvertCertsToTree_SpiffeIDFieldSafeWithMaliciousURISAN(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Construct a URI with a control char in the path. CreateCertificate calls
	// uri.String() which percent-encodes \x1b → %1b; the SPIFFE library then
	// rejects the percent sign as an invalid path segment char.
	maliciousURI := &url.URL{Scheme: "spiffe", Host: "example.com", Path: "/work\x1bload"}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{maliciousURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	opts := X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "issuer", "spiffe-id"}}}
	out, err := convertCertsToTree([]*x509.Certificate{root, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)

	// No C0 (except structural \n/\t), DEL, or C1 rune must appear in the output.
	for byteOff, r := range out {
		if r == '\n' || r == '\t' {
			continue
		}
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			t.Errorf("output rune at byte offset %d is a control character: U+%04X", byteOff, r)
		}
	}
	// The SPIFFE library rejects URIs with percent-encoded bytes in the path, so
	// the spiffe-id field must show the safe fallback value, not an empty string.
	assert.Contains(t, out, "(none)", "spiffe-id field must fall back to '(none)' for rejected malicious URI")
}
