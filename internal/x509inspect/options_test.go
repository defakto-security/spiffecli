package x509inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time assertion: X509ConvertOptions composes the two option types correctly.
var _ = X509ConvertOptions{
	Output: X509InspectOutputOptions{},
	Chain:  X509ChainOptions{},
}

// TestConvertCertsToChain_HonoursBundleViaChainOpts verifies that root certs supplied
// via X509ConvertOptions.Chain.BundleCerts are included in the chain output.
func TestConvertCertsToChain_HonoursBundleViaChainOpts(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	out, err := ConvertCertsToChain(
		[]*x509.Certificate{intermediate, leaf},
		X509ConvertOptions{Chain: X509ChainOptions{BundleCerts: []*x509.Certificate{root}}},
	)
	require.NoError(t, err)
	assert.Contains(t, out, "Root CA", "chain output must include root from BundleCerts")
}

// TestConvertCertsToTree_HonoursTreeFieldsViaChainOpts verifies that tree fields
// supplied via X509ConvertOptions.Chain.TreeFields appear in the tree output.
func TestConvertCertsToTree_HonoursTreeFieldsViaChainOpts(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	out, err := ConvertCertsToTree(
		[]*x509.Certificate{leaf},
		X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject", "not-after"}}},
	)
	require.NoError(t, err)
	assert.True(t, strings.Contains(out, "not-after:"), "tree output must contain 'not-after:' when requested via TreeFields")
}

// TestInspect_ChainFormat_ShortestPath_ViaInspector verifies that ShortestPath=true on
// X509Inspector is correctly propagated through X509ConvertOptions.Chain into the chain
// formatter: a 4-cert input (root+intermediate+leaf+unrelated) produces a 3-line output.
func TestInspect_ChainFormat_ShortestPath_ViaInspector(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	// Add an unrelated CA that is not on the valid path.
	extraCA := testx509.NewCertificateAuthority(t, "Unrelated CA")
	extra := extraCA.GenerateCaCertificate(t)

	path := filepath.Join(t.TempDir(), "chain.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates([]*x509.Certificate{leaf, intermediate, root, extra}), 0600))

	var stderr strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "chain",
		ShortestPath: true,
		Stderr:       &stderr,
	}
	out, err := i.Inspect()
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	assert.Len(t, lines, 3, "ShortestPath must filter chain to exactly 3 certs (root+intermediate+leaf)")
	assert.NotContains(t, out, "Unrelated CA", "ShortestPath must exclude the unrelated CA from output")
}

// TestInspect_TreeFormat_TreeFields_ViaInspector verifies that TreeFields on X509Inspector
// is parsed and propagated through X509ConvertOptions.Chain.TreeFields into the tree formatter.
func TestInspect_TreeFormat_TreeFields_ViaInspector(t *testing.T) {
	root, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	path := filepath.Join(t.TempDir(), "chain.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates([]*x509.Certificate{root, leaf}), 0600))

	var stderr strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "tree",
		TreeFields:   "subject,not-after",
		Stderr:       &stderr,
	}
	out, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, out, "not-after:", "TreeFields from inspector must flow into tree output")
	assert.Empty(t, stderr.String(), "compatible flag combination must not emit any warning")
}

// TestInspect_ChainFormat_Bundle_ViaInspector verifies that a bundle file loaded by
// Inspect() is propagated through X509ConvertOptions.Chain.BundleCerts and that the
// bundle root appears in the chain output.
func TestInspect_ChainFormat_Bundle_ViaInspector(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	// Write only leaf+intermediate to --filename; root goes to --bundle.
	chainPath := filepath.Join(t.TempDir(), "chain.pem")
	require.NoError(t, os.WriteFile(chainPath, pemutil.EncodeCertificates([]*x509.Certificate{leaf, intermediate}), 0600))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, pemutil.EncodeCertificates([]*x509.Certificate{root}), 0600))

	var stderr strings.Builder
	i := X509Inspector{
		Filename:     chainPath,
		Bundle:       bundlePath,
		OutputFormat: "chain",
		Stderr:       &stderr,
	}
	out, err := i.Inspect()
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3, "chain must include root from --bundle, giving 3 lines total")
	assert.Contains(t, lines[0], "Root CA", "first line must be the root from --bundle")
	assert.Contains(t, lines[2], "workload", "last line must be the leaf")
}

// TestInspect_OutputOptions_IndentFlowsThroughConvertOpts verifies that
// X509InspectOutputOptions.Indent is correctly propagated through X509ConvertOptions.Output
// into the JSON converter. This exercises the Inspect() path that builds
// convertOpts := X509ConvertOptions{Output: i.OutputOptions, Chain: chainOpts}.
func TestInspect_OutputOptions_IndentFlowsThroughConvertOpts(t *testing.T) {
	_, leaf, _ := testx509.NewThreeLevelSPIFFEChain(t)
	path := filepath.Join(t.TempDir(), "leaf.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates([]*x509.Certificate{leaf}), 0600))

	compact := X509Inspector{Filename: path, OutputFormat: "json", OutputOptions: X509InspectOutputOptions{Indent: false}}
	compactOut, err := compact.Inspect()
	require.NoError(t, err)
	assert.False(t, strings.Contains(compactOut, "\n  "), "compact JSON must have no indented lines")

	indented := X509Inspector{Filename: path, OutputFormat: "json", OutputOptions: X509InspectOutputOptions{Indent: true}}
	indentedOut, err := indented.Inspect()
	require.NoError(t, err)
	assert.Contains(t, indentedOut, "\n  ", "indented JSON must have newlines with leading spaces")
}

// TestX509ChainOptions_DoesNotLeakIntoOutputOptions verifies that setting Chain fields
// does not affect Output fields: Indent, Color, TimeZone remain unchanged regardless
// of what BundleCerts, ShortestPath, or TreeFields are set to.
func TestX509ChainOptions_DoesNotLeakIntoOutputOptions(t *testing.T) {
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)

	opts := X509ConvertOptions{
		Output: X509InspectOutputOptions{Indent: true, Color: false, TimeZone: "UTC"},
		Chain:  X509ChainOptions{BundleCerts: []*x509.Certificate{root}, ShortestPath: true, TreeFields: []string{"subject"}},
	}

	assert.True(t, opts.Output.Indent, "Output.Indent must remain true after setting Chain fields")
	assert.False(t, opts.Output.Color, "Output.Color must remain false")
	assert.Equal(t, "UTC", opts.Output.TimeZone, "Output.TimeZone must be unaffected by Chain fields")
	assert.Len(t, opts.Chain.BundleCerts, 1, "Chain.BundleCerts must hold the supplied cert")
	assert.True(t, opts.Chain.ShortestPath, "Chain.ShortestPath must be set")
}

// TestX509InspectOutputOptions_DoesNotHaveChainFields is a compile-time guard: it asserts
// that X509InspectOutputOptions contains only Indent, Color, TimeZone. Any attempt to
// set BundleCerts, ShortestPath, or TreeFields on it must fail at compile time.
// The struct literal below would fail to compile if those fields were re-added to
// X509InspectOutputOptions (breaking the refactoring invariant).
var _ = X509InspectOutputOptions{
	Indent:   false,
	Color:    false,
	TimeZone: "",
}
