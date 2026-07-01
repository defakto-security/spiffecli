package x509inspect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/inspect"
	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/defakto-security/spiffecli/internal/style"
	"github.com/defakto-security/spiffecli/internal/test/testkey"
	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Compile-time assertion: X509InspectOutputOptions must satisfy style.OutputOptions.
// This lives in inspector_test.go because X509InspectOutputOptions is now defined in
// inspector.go; the assertion fails at compile time if InColor() is ever removed.
var _ style.OutputOptions = X509InspectOutputOptions{}

var update = flag.Bool("update", false, "update golden files")

var (
	fixtureCAKey                 = testkey.EC256()
	fixtureLeafKey               = testkey.EC256()
	fixtureIntermediateKey       = testkey.EC256()
	fixtureStaleIntermediateAKey = testkey.EC256()
	fixtureStaleIntermediateBKey = testkey.EC256()
)

// newCAAndLeafSVID wraps testx509.NewConformantSVID for backwards-compatible call sites in this file.
func newCAAndLeafSVID(t *testing.T, spiffeID string) (*x509.Certificate, *x509.Certificate, crypto.Signer) {
	t.Helper()
	return testx509.NewConformantSVID(t, spiffeID)
}

// writeCerts writes one or more certificates to a temp PEM file and returns the path.
func writeCerts(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certs.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates(certs), 0600))
	return path
}

// ---- Bundle flag tests ----

func TestInspector_Bundle_FileNotFound(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, Bundle: "testdata/nonexistent.pem", OutputFormat: "chain"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file")
}

func TestInspector_Bundle_NoCertificatesInFile(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	bundlePath := filepath.Join(t.TempDir(), "empty-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte("not a PEM file\n"), 0600))

	i := X509Inspector{Filename: path, Bundle: bundlePath, OutputFormat: "chain"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file")
}

func TestInspector_Bundle_EmptyFile(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	bundlePath := filepath.Join(t.TempDir(), "empty-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, []byte{}, 0600))

	i := X509Inspector{Filename: path, Bundle: bundlePath, OutputFormat: "chain"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file")
}

func TestInspector_Bundle_LoadsSuccessfully(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)
	bundlePath := writeCerts(t, caCert)

	// Capture stderr to suppress any warnings (bundle is ignored for non-chain/tree formats).
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "json",
		Stderr:       &strings.Builder{},
	}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.NotEmpty(t, output)
	// Output must contain only the certs from --filename, not --bundle.
	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1, "output must contain only the certs from --filename, not --bundle")
}

// ---- IsSvid + new flags ----

func TestInspector_IsSvid_IgnoresBundle(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	// Bundle points to a non-existent file; --isSvid should succeed without loading it.
	i := X509Inspector{Filename: path, IsSvid: true, Bundle: "testdata/nonexistent.pem"}
	output, err := i.Inspect()
	require.NoError(t, err, "--isSvid must ignore --bundle and not error")
	assert.Empty(t, output)
}

func TestInspector_IsSvid_IgnoresShortestPath(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, IsSvid: true, ShortestPath: true}
	output, err := i.Inspect()
	require.NoError(t, err, "--isSvid must ignore --shortest-path")
	assert.Empty(t, output)
}

func TestInspector_IsSvid_IgnoresTreeFields(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, IsSvid: true, TreeFields: "subject,serial"}
	output, err := i.Inspect()
	require.NoError(t, err, "--isSvid must ignore --tree-fields")
	assert.Empty(t, output)
}

// ---- Warning messages ----

func TestInspector_Warnings_ShortestPath_WithTree(t *testing.T) {
	var buf strings.Builder
	i := X509Inspector{
		Filename:     "testdata/chain-3-deep.pem",
		OutputFormat: "tree",
		ShortestPath: true,
		Stderr:       &buf,
	}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--shortest-path is ignored with --format "tree"`)
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "└─")
	assert.Contains(t, output, "test-workload")
}

func TestInspector_Warnings_ShortestPath_WithSummary(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "summary",
		ShortestPath: true,
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	// Warning must include the format name.
	assert.Contains(t, buf.String(), `--shortest-path is ignored with --format "summary"`)
}

func TestInspector_Warnings_TreeFields_WithJson(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "json",
		TreeFields:   "subject,serial",
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--tree-fields is ignored with --format "json"`)
}

func TestInspector_Warnings_TreeFields_WithYaml(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "yaml",
		TreeFields:   "subject,not-after",
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--tree-fields is ignored with --format "yaml"`)
}

func TestInspector_Warnings_NoWarning_WhenFlagsCompatible(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	// No ShortestPath, no TreeFields → no warnings.
	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "json",
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	assert.Empty(t, buf.String(), "no incompatible flags means no warnings")
}

// TestInspector_Warnings_NoWarning_EmptyTreeFields_NonTreeFormat is a regression guard
// for PR #58 review comment thread 8/29. When TreeFields == "" (zero value, as set by
// cobra when the flag is omitted), no "--tree-fields is ignored" warning must be emitted
// for any non-tree format. A refactor that re-introduces a non-empty default for TreeFields
// inside Inspect() would cause this test to fail.
func TestInspector_Warnings_NoWarning_EmptyTreeFields_NonTreeFormat(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	leafPath := writeCerts(t, leaf)

	// For chain format we need a valid chain PEM (leaf alone is fine; chain builder
	// treats it as a single-node degenerate chain).
	_, ca, _ := newCAAndLeafSVID(t, "spiffe://example.com/ca")
	chainPath := writeCerts(t, ca, leaf)

	tests := []struct {
		format string
		path   string
	}{
		{"json", leafPath},
		{"yaml", leafPath},
		{"summary", leafPath},
		{"chain", chainPath},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf strings.Builder
			i := X509Inspector{
				Filename:     tt.path,
				OutputFormat: tt.format,
				// TreeFields intentionally left as "" (zero value).
				Stderr: &buf,
			}
			_, err := i.Inspect()
			require.NoError(t, err)
			assert.NotContains(t, buf.String(), "--tree-fields is ignored",
				"empty TreeFields must not emit a spurious warning for --format %s", tt.format)
		})
	}
}

func TestInspector_Warnings_NoWarning_IsSvid(t *testing.T) {
	// --isSvid exits before the warning logic; no warnings should be emitted.
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		IsSvid:       true,
		ShortestPath: true,
		TreeFields:   "subject,serial",
		Stderr:       &buf,
	}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Empty(t, output)
	assert.Empty(t, buf.String(), "--isSvid path must not emit warnings")
}

// ---- Additional warning coverage ----

func TestInspector_Warnings_ShortestPath_WithYaml(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "yaml",
		ShortestPath: true,
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--shortest-path is ignored with --format "yaml"`)
}

func TestInspector_Warnings_TreeFields_WithSummary(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "summary",
		TreeFields:   "subject,not-after",
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--tree-fields is ignored with --format "summary"`)
}

func TestInspector_Warnings_BothFlags_AtOnce(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "json",
		ShortestPath: true,
		TreeFields:   "subject,serial",
		Stderr:       &buf,
	}
	_, err := i.Inspect()
	require.NoError(t, err)
	warnings := buf.String()
	assert.Contains(t, warnings, `--shortest-path is ignored with --format "json"`)
	assert.Contains(t, warnings, `--tree-fields is ignored with --format "json"`)
}

func TestInspector_Warnings_NoWarning_ShortestPath_WithChainFormat(t *testing.T) {
	// ShortestPath + chain is the documented valid combination — no warning should be emitted.
	// Inspect() may still return an error (e.g., no trusted root found for --shortest-path against
	// a single self-issued leaf), but the test only asserts on stderr warning content, so the error
	// return is intentionally discarded.
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "chain",
		ShortestPath: true,
		Stderr:       &buf,
	}
	_, _ = i.Inspect()
	assert.Empty(t, buf.String(), "--shortest-path with --format chain must not emit a warning")
}

func TestInspector_Warnings_NoWarning_TreeFields_WithTreeFormat(t *testing.T) {
	// TreeFields + tree is the documented valid combination — no warning should be emitted.
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		OutputFormat: "tree",
		TreeFields:   "subject,serial",
		Stderr:       &buf,
	}
	_, _ = i.Inspect()
	assert.Empty(t, buf.String(), "--tree-fields with --format tree must not emit a warning")
}

func TestInspector_Bundle_PrivateKeyOnlyPEM(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	bundlePath := filepath.Join(t.TempDir(), "key-only-bundle.pem")
	require.NoError(t, os.WriteFile(bundlePath, pemBytes, 0600))

	i := X509Inspector{Filename: path, Bundle: bundlePath, OutputFormat: "chain"}
	_, err = i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file")
}

func TestInspector_Warnings_Bundle_WithJSON(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "json",
		Stderr:       &buf,
	}
	_, err = i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--bundle is ignored with --format "json"`)
}

func TestInspector_Warnings_Bundle_WithYAML(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "yaml",
		Stderr:       &buf,
	}
	_, err = i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--bundle is ignored with --format "yaml"`)
}

func TestInspector_Warnings_Bundle_WithSummary(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "summary",
		Stderr:       &buf,
	}
	_, err = i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, buf.String(), `--bundle is ignored with --format "summary"`)
}

func TestInspector_Warnings_NoWarning_Bundle_WithChain(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "chain",
		Stderr:       &buf,
	}
	_, _ = i.Inspect()
	assert.NotContains(t, buf.String(), "--bundle is ignored", "--bundle with --format chain must not emit a warning")
}

func TestInspector_Warnings_NoWarning_Bundle_WithTree(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		OutputFormat: "tree",
		Stderr:       &buf,
	}
	_, _ = i.Inspect()
	assert.NotContains(t, buf.String(), "--bundle is ignored", "--bundle with --format tree must not emit a warning")
}

func TestInspector_Bundle_IOSkipped_OnJSON(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       "/nonexistent/bundle.pem",
		OutputFormat: "json",
		Stderr:       &buf,
	}
	output, err := i.Inspect()
	require.NoError(t, err, "nonexistent bundle must not cause an error when format is json (load is skipped)")
	assert.NotEmpty(t, output, "JSON output must still be produced")
	assert.Contains(t, buf.String(), `--bundle is ignored with --format "json"`)
}

func TestInspector_Bundle_IOStillRuns_OnChain(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{
		Filename:     path,
		Bundle:       "/nonexistent/bundle.pem",
		OutputFormat: "chain",
	}
	_, err := i.Inspect()
	require.Error(t, err, "nonexistent bundle must cause an error when format is chain (load is attempted)")
	assert.Contains(t, err.Error(), "failed to read certificates from file")
}

// TestInspector_Warnings_Bundle_WithJSON_DoesNotReadFile and its yaml/summary siblings prove
// that when --format is not chain/tree, the bundle file is never opened — not just warned about.
// Each subtest points Bundle at a path inside t.TempDir() that is never created, so any
// attempt to load the file would return a "file not found" error.
func TestInspector_Warnings_Bundle_DoesNotReadFile(t *testing.T) {
	tests := []struct {
		format  string
		warning string
	}{
		{"json", `--bundle is ignored with --format "json"`},
		{"yaml", `--bundle is ignored with --format "yaml"`},
		{"summary", `--bundle is ignored with --format "summary"`},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
			path := writeCerts(t, leaf)

			nonExistentBundle := filepath.Join(t.TempDir(), "does-not-exist.pem")
			// Deliberately do NOT create the file — any I/O attempt must be observable as an error.

			var buf strings.Builder
			i := X509Inspector{
				Filename:     path,
				Bundle:       nonExistentBundle,
				OutputFormat: tt.format,
				Stderr:       &buf,
			}
			output, err := i.Inspect()
			require.NoError(t, err, "nonexistent bundle must not cause an error when format is %s (I/O must be skipped)", tt.format)
			assert.NotEmpty(t, output)
			assert.Contains(t, buf.String(), tt.warning)
		})
	}
}

func TestInspector_Warnings_AllThreeFlags_WithJSON(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	var buf strings.Builder
	i := X509Inspector{
		Filename:     path,
		Bundle:       bundlePath,
		ShortestPath: true,
		TreeFields:   "subject,serial",
		OutputFormat: "json",
		Stderr:       &buf,
	}
	_, err = i.Inspect()
	require.NoError(t, err)
	warnings := buf.String()
	assert.Contains(t, warnings, `--bundle is ignored with --format "json"`)
	assert.Contains(t, warnings, `--shortest-path is ignored with --format "json"`)
	assert.Contains(t, warnings, `--tree-fields is ignored with --format "json"`)
}

func TestInspector_TreeFields_TrimsWhitespaceAndDropsEmpties(t *testing.T) {
	ca, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, ca, leaf)
	leafSubject := leaf.Subject.String()

	tests := []struct {
		name         string
		treeFields   string
		wantContains []string
	}{
		{
			name:         "space_after_comma",
			treeFields:   "subject, serial",
			wantContains: []string{leafSubject, "serial:"},
		},
		{
			name:         "trailing_comma",
			treeFields:   "subject,",
			wantContains: []string{leafSubject},
		},
		{
			name:         "leading_comma",
			treeFields:   ",subject",
			wantContains: []string{leafSubject},
		},
		{
			name:         "double_comma",
			treeFields:   "subject,,serial",
			wantContains: []string{leafSubject, "serial:"},
		},
		{
			name:         "spaces_around_all_fields",
			treeFields:   " subject , spiffe-id , not-after ",
			wantContains: []string{leafSubject, "not-after:"},
		},
		{
			name:         "only_comma_falls_back_to_subject",
			treeFields:   ",",
			wantContains: []string{leafSubject},
		},
		{
			name:         "only_whitespace_falls_back_to_subject",
			treeFields:   "   ",
			wantContains: []string{leafSubject},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := X509Inspector{
				Filename:     path,
				OutputFormat: "tree",
				TreeFields:   tt.treeFields,
				Stderr:       &strings.Builder{},
			}
			output, err := i.Inspect()
			require.NoError(t, err)
			require.NotEmpty(t, output)
			for _, want := range tt.wantContains {
				assert.Contains(t, output, want)
			}
		})
	}
}

// ---- Inspector flag / error tests ----

func TestInspector_NoFile(t *testing.T) {
	i := X509Inspector{}
	_, err := i.Inspect()
	require.ErrorContains(t, err, "must specify a file")
}

func TestInspector_FileNotFound(t *testing.T) {
	i := X509Inspector{Filename: "testdata/nonexistent.pem", OutputFormat: "json"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file")
}

func TestInspector_NoCertificatesInFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(path, []byte("this is not a PEM file\n"), 0600))

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file")
}

func TestInspector_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(path, []byte{}, 0600))

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file")
}

func TestInspector_PrivateKeyOnlyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	path := filepath.Join(t.TempDir(), "key-only.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	_, err = i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file")
}

func TestInspector_UnsupportedFormat(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "unsupported"}
	_, err := i.Inspect()
	require.ErrorContains(t, err, `output format "unsupported" not supported`)
}

// TestInspector_Warnings_FormatValue_Sanitized is a regression test for PR #58 review
// thread 23/29. It proves that a --format value containing ANSI escape sequences and
// other control characters is escaped (not interpreted) when it surfaces in stderr
// warnings and in the unsupported-format error returned from Inspect().
func TestInspector_Warnings_FormatValue_Sanitized(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	leafPath := writeCerts(t, leaf)

	maliciousFormat := "summary\x1b[2J\x1b[H\x07"

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Bundle CA", testx509.WithSigner(caKey))
	bundlePath := writeCerts(t, ca.GenerateCaCertificate(t))

	// All three warning branches fire: Bundle != "", ShortestPath == true, TreeFields != "".
	var buf strings.Builder
	i := X509Inspector{
		Filename:     leafPath,
		Bundle:       bundlePath,
		ShortestPath: true,
		TreeFields:   "subject",
		OutputFormat: maliciousFormat,
		Stderr:       &buf,
	}
	// Inspect() returns an unsupported-format error because maliciousFormat is not in FormatMap.
	_, inspectErr := i.Inspect()
	require.Error(t, inspectErr)

	stderrOutput := buf.String()
	// No raw ESC byte (0x1b) must appear in stderr.
	assert.NotContains(t, stderrOutput, "\x1b", "stderr must not contain raw ESC byte")
	// %q produces the literal backslash-x sequence; assert its presence.
	assert.Contains(t, stderrOutput, `\x1b`, "stderr must contain the %q-escaped form of ESC")
	// No raw \r or bell must leak either.
	assert.NotContains(t, stderrOutput, "\r")
	assert.NotContains(t, stderrOutput, "\x07")

	// The returned error also must not contain raw ESC.
	errStr := inspectErr.Error()
	assert.NotContains(t, errStr, "\x1b", "error string must not contain raw ESC byte")
	assert.Contains(t, errStr, `\x1b`, "error string must contain the %q-escaped form of ESC")
}

// ---- JSON output ----

func TestInspector_JSON_SingleCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)

	assert.Equal(t, "spiffe://example.com/workload", certs[0].SpiffeID)
	assert.Equal(t, "example.com", certs[0].TrustDomain)
	assert.Equal(t, "/workload", certs[0].Path)
	assert.Equal(t, "ECDSA P-256", certs[0].KeyAlgorithm)
	assert.False(t, certs[0].IsCA)
	assert.NotEmpty(t, certs[0].SHA256Fingerprint)
	assert.Contains(t, certs[0].KeyUsage, "digitalSignature")
}

func TestInspector_JSON_Indent(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "json", OutputOptions: X509InspectOutputOptions{Indent: true}}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, output, "\n  ")
}

func TestInspector_JSON_MultiCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")

	caKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca2 := testx509.NewCertificateAuthority(t, "Intermediate CA", testx509.WithSigner(caKey2))
	intCert := ca2.GenerateCaCertificate(t)

	path := writeCerts(t, leaf, intCert)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 2)

	// First cert is the leaf SVID
	assert.Equal(t, "spiffe://example.com/workload", certs[0].SpiffeID)
	// Second cert is the intermediate (no SPIFFE ID)
	assert.Empty(t, certs[1].SpiffeID)
	assert.True(t, certs[1].IsCA)
}

func TestInspector_JSON_NoSpiffeFields_WhenNotSVID(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)
	path := writeCerts(t, caCert)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.Empty(t, certs[0].SpiffeID)
	assert.Empty(t, certs[0].TrustDomain)
	assert.Empty(t, certs[0].Path)
}

func TestInspector_JSON_SpiffeIDError_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "spiffe_id_error", "JSON output should include stable error code field")
	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.NotEmpty(t, certs[0].SpiffeIDError)
	assert.Empty(t, certs[0].SpiffeID)
}

func TestInspector_JSON_SpiffeIDError_OmittedWhenEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "spiffe_id_error", "valid SVID should omit error code field")
}

func TestInspector_YAML_SpiffeIDError_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "spiffe_id_error", "YAML output should include stable error code field")
	var certs []CertificateInfo
	require.NoError(t, yaml.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.NotEmpty(t, certs[0].SpiffeIDError)
	assert.Empty(t, certs[0].SpiffeID)
}

func TestInspector_YAML_SpiffeIDError_OmittedWhenEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "spiffe_id_error", "valid SVID should omit error code field")
}

func TestInspector_JSON_SpiffeIDErrorDetail_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "spiffe_id_error_detail", "JSON output should include error detail field for malformed SPIFFE URI")
	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.Equal(t, SpiffeIDErrorInvalidURI, certs[0].SpiffeIDError)
	assert.Equal(t, "URI is not a valid SPIFFE ID", certs[0].SpiffeIDErrorDetail,
		"JSON SpiffeIDErrorDetail must be the stable fixed string, not raw library text")
}

func TestInspector_JSON_SpiffeIDErrorDetail_OmittedWhenEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "spiffe_id_error_detail", "valid SVID should omit error detail field")
}

func TestInspector_YAML_SpiffeIDErrorDetail_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "spiffe_id_error_detail", "YAML output should include error detail field for malformed SPIFFE URI")
	var certs []CertificateInfo
	require.NoError(t, yaml.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.Equal(t, SpiffeIDErrorInvalidURI, certs[0].SpiffeIDError)
	assert.Equal(t, "URI is not a valid SPIFFE ID", certs[0].SpiffeIDErrorDetail,
		"YAML SpiffeIDErrorDetail must be the stable fixed string, not raw library text")
}

func TestInspector_YAML_SpiffeIDErrorDetail_OmittedWhenEmpty(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "spiffe_id_error_detail", "valid SVID should omit error detail field")
}

// newCertWithMalformedSpiffeURI creates a leaf cert whose only URI SAN is spiffe:// (no trust domain),
// which fails spiffeid.FromURI but has the right scheme — the canonical malformed-SPIFFE test fixture.
func newCertWithMalformedSpiffeURI(t *testing.T) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	malformedURI, err := url.Parse("spiffe://")
	require.NoError(t, err)
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "malformed-spiffe"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{malformedURI},
	}
	return testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
}

// ---- YAML output ----

func TestInspector_YAML_SingleCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, yaml.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.Equal(t, "spiffe://example.com/workload", certs[0].SpiffeID)
}

func TestInspector_YAML_MultiCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")

	caKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca2 := testx509.NewCertificateAuthority(t, "Intermediate CA", testx509.WithSigner(caKey2))
	intCert := ca2.GenerateCaCertificate(t)

	path := writeCerts(t, leaf, intCert)

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, yaml.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 2)
}

// ---- Summary output ----

func TestInspector_Summary_SingleCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "spiffe://example.com/workload")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "Expires in")
	assert.Contains(t, output, "ECDSA P-256")
}

func TestInspector_Summary_ExpiredCert(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/old")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	expiredCert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	path := writeCerts(t, expiredCert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, output, "Expired at")
}

func TestInspector_Summary_MultiCert(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")

	caKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca2 := testx509.NewCertificateAuthority(t, "Int CA", testx509.WithSigner(caKey2))
	intCert := ca2.GenerateCaCertificate(t)

	path := writeCerts(t, leaf, intCert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "Certificate 1 of 2")
	assert.Contains(t, output, "Certificate 2 of 2")
}

func TestInspector_Summary_Timezone(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{
		Filename:      path,
		OutputFormat:  "summary",
		OutputOptions: X509InspectOutputOptions{TimeZone: "UTC"},
	}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.NotEmpty(t, output)
}

func TestInspector_Summary_InvalidTimezone(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{
		Filename:      path,
		OutputFormat:  "summary",
		OutputOptions: X509InspectOutputOptions{TimeZone: "Not/AReal/Zone"},
	}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error loading timezone")
}

// ---- Color output ----

func TestInspector_Color_JSON(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{
		Filename:      path,
		OutputFormat:  "json",
		OutputOptions: X509InspectOutputOptions{Color: true},
	}
	_, err := i.Inspect()
	require.NoError(t, err)
}

// ---- isSvid conformance ----

func TestIsSvid_Conformant(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	ok, reasons := checkIsSvid(leaf)
	assert.True(t, ok)
	assert.Empty(t, reasons)
}

func TestIsSvid_NoURISAN(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-san"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate has no URI SAN")
}

func TestIsSvid_MultipleURISANs(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "multi-san"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate has more than one URI SAN")
}

func TestIsSvid_InvalidSpiffeID(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	badURI, _ := url.Parse("https://not-a-spiffe-id.example.com")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bad-san"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{badURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	found := false
	for _, r := range reasons {
		if len(r) > 0 && strings.Contains(r, "not a valid SPIFFE ID") {
			found = true
		}
	}
	assert.True(t, found, "expected a reason about invalid SPIFFE ID; got: %v", reasons)
}

// TestIsSvid_InvalidSpiffeID_ReasonIsFixedString pins the exact reason string
// returned when a URI SAN fails spiffeid.FromURI. The string must be the stable
// fixed value "URI SAN is not a valid SPIFFE ID" — no embedded library error text.
// This guards against regressions where fmt.Sprintf is reintroduced and leaks
// implementation-specific error messages into the conformance output.
func TestIsSvid_InvalidSpiffeID_ReasonIsFixedString(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	badURI, _ := url.Parse("https://not-a-spiffe-id.example.com")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bad-san"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{badURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	// assert.Contains on a []string checks for exact element membership,
	// so this fails if the reason has any suffix (e.g., ": <library error>").
	assert.Contains(t, reasons, "URI SAN is not a valid SPIFFE ID",
		"reason must be the exact fixed string, not a formatted message with embedded library error")
}

// TestIsSvid_InvalidSpiffeID_NoTerminalInjection verifies that a certificate whose URI SAN
// contains ANSI escape sequences (ESC = 0x1b) does not cause control characters to appear in
// any conformance reason string. This directly exercises the terminal-injection attack vector:
// a malicious cert author embedding escape sequences in the URI, hoping they propagate into
// operator-visible output via an embedded error message. We construct the cert struct directly
// to bypass Go's url.Parse validation (which would percent-encode \x1b during DER round-trip).
func TestIsSvid_InvalidSpiffeID_NoTerminalInjection(t *testing.T) {
	maliciousURI := &url.URL{
		Scheme: "spiffe",
		Host:   "\x1b[31mevil\x1b[0m.example.com",
		Path:   "/path",
	}
	cert := &x509.Certificate{
		URIs:                  []*url.URL{maliciousURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)

	for _, r := range reasons {
		assert.NotContains(t, r, "\x1b", "reason must not contain ESC (0x1b): %q", r)
		for _, b := range []byte(r) {
			assert.False(t, b < 0x20, "reason contains C0 control character 0x%02x in %q", b, r)
		}
	}
	assert.Contains(t, reasons, "URI SAN is not a valid SPIFFE ID")
}

// TestInspect_IsSvid_MaliciousCertNoTerminalInjection tests the end-to-end Inspect() path
// with a PEM file whose raw DER bytes contain \x1b in the URI SAN extension. Go 1.22+
// rejects this URI during x509.ParseCertificate (percent-encoding produces %1B which is an
// invalid URL escape), so the error comes from file loading rather than the conformance check.
// The invariant tested here is: no matter which error path fires, the returned error must
// not expose control characters to the caller.
func TestInspect_IsSvid_MaliciousCertNoTerminalInjection(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	maliciousURI := &url.URL{
		Scheme: "spiffe",
		Host:   "\x1b[31mevil\x1b[0m.example.com",
		Path:   "/path",
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "malicious"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{maliciousURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "malicious.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))

	i := X509Inspector{Filename: path, IsSvid: true}
	_, inspectErr := i.Inspect()

	require.Error(t, inspectErr, "a cert with malicious URI must produce an error")
	errStr := inspectErr.Error()
	assert.NotContains(t, errStr, "\x1b", "error must not contain ESC (0x1b)")
	for _, b := range []byte(errStr) {
		assert.False(t, b < 0x20, "error contains C0 control character 0x%02x in %q", b, errStr)
	}
}

func TestIsSvid_IsCA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)

	ok, reasons := checkIsSvid(caCert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate has IsCA=true (leaf certificates must not be a CA)")
}

func TestIsSvid_MissingDigitalSignature(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment, // no digitalSignature
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate key usage does not include digitalSignature")
}

func TestIsSvid_KeyCertSign(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate key usage includes keyCertSign (not allowed for leaf SVIDs)")
}

func TestIsSvid_DisallowedEKU(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "extended key usage contains disallowed value: codeSigning")
}

// newCertWithUnknownEKUOID creates a leaf cert whose EKU extension contains only a custom OID
// that Go's x509 parser does not recognize, causing it to land in cert.UnknownExtKeyUsage.
func newCertWithUnknownEKUOID(t *testing.T, oid asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")

	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{oid})
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unknown-eku"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuValue},
		},
	}
	return testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
}

func TestIsSvid_UnknownExtKeyUsageOID(t *testing.T) {
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	cert := newCertWithUnknownEKUOID(t, customOID)
	require.NotEmpty(t, cert.UnknownExtKeyUsage, "precondition: cert must have unknown EKU OIDs")

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)

	var foundReason string
	for _, r := range reasons {
		if strings.Contains(r, "disallowed unknown OID") {
			foundReason = r
			break
		}
	}
	require.NotEmpty(t, foundReason, "expected a reason about disallowed unknown OID; got: %v", reasons)
	assert.Contains(t, foundReason, "1.2.3.4.5.6.7", "reason must include the OID dotted-decimal representation")
}

// newCertWithUnknownEKUOIDs creates a leaf cert whose EKU extension contains multiple custom OIDs,
// all of which will land in cert.UnknownExtKeyUsage because Go's x509 parser doesn't recognize them.
func newCertWithUnknownEKUOIDs(t *testing.T, oids []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")

	ekuValue, err := asn1.Marshal(oids)
	require.NoError(t, err)

	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "multi-unknown-eku"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuValue},
		},
	}
	return testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
}

// TestIsSvid_MultipleUnknownExtKeyUsageOIDs verifies that each unknown EKU OID
// generates its own reason string so callers can see exactly which OIDs violated the spec.
func TestIsSvid_MultipleUnknownExtKeyUsageOIDs(t *testing.T) {
	oid1 := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	oid2 := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 8}
	cert := newCertWithUnknownEKUOIDs(t, []asn1.ObjectIdentifier{oid1, oid2})
	require.Len(t, cert.UnknownExtKeyUsage, 2, "precondition: cert must have exactly 2 unknown EKU OIDs")

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)

	var unknownReasons []string
	for _, r := range reasons {
		if strings.Contains(r, "disallowed unknown OID") {
			unknownReasons = append(unknownReasons, r)
		}
	}
	assert.Len(t, unknownReasons, 2, "expected one reason per unknown OID; got: %v", reasons)

	combined := strings.Join(unknownReasons, "\n")
	assert.Contains(t, combined, "1.2.3.4.5.6.7", "first OID must appear in reasons")
	assert.Contains(t, combined, "1.2.3.4.5.6.8", "second OID must appear in reasons")
}

// TestIsSvid_KnownAllowedPlusUnknownEKU verifies that a cert with an allowed EKU (serverAuth)
// combined with an unknown OID still fails conformance — the unknown OID is never permitted.
func TestIsSvid_KnownAllowedPlusUnknownEKU(t *testing.T) {
	// serverAuth OID (1.3.6.1.5.5.7.3.1) is allowed; the custom OID is not.
	serverAuthOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	cert := newCertWithUnknownEKUOIDs(t, []asn1.ObjectIdentifier{serverAuthOID, customOID})

	// serverAuth should be recognized; the custom OID should land in UnknownExtKeyUsage.
	require.NotEmpty(t, cert.UnknownExtKeyUsage,
		"precondition: custom OID must land in UnknownExtKeyUsage")
	require.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth,
		"precondition: serverAuth must be recognized and in ExtKeyUsage")

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok, "cert must fail because of the unknown OID even though serverAuth is allowed")

	var foundUnknownReason bool
	for _, r := range reasons {
		if strings.Contains(r, "disallowed unknown OID") && strings.Contains(r, "1.2.3.4.5.6.7") {
			foundUnknownReason = true
			break
		}
	}
	assert.True(t, foundUnknownReason, "expected reason naming the unknown OID; got: %v", reasons)

	// serverAuth must not produce a violation reason.
	for _, r := range reasons {
		assert.NotContains(t, r, "serverAuth", "serverAuth is allowed and must not appear in reasons")
	}
}

// ---- IsSvid flag on inspector ----

// TestInspector_IsSvid_NoCertificatesInFile verifies that --isSvid with a file
// containing no CERTIFICATE blocks returns an error instead of a false positive pass.
func TestInspector_IsSvid_NoCertificatesInFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(path, []byte("this is not a PEM file\n"), 0600))

	i := X509Inspector{Filename: path, IsSvid: true}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file",
		"--isSvid must error on no-cert input, not report conformance")
}

// TestInspector_IsSvid_FileNotFound verifies that --isSvid with a nonexistent file
// returns an error instead of a false positive pass.
func TestInspector_IsSvid_FileNotFound(t *testing.T) {
	i := X509Inspector{Filename: "testdata/nonexistent.pem", IsSvid: true}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file",
		"--isSvid must error on unreadable input, not report conformance")
}

// TestInspector_IsSvid_EmptyFile verifies that --isSvid with a completely empty file
// returns a "no certificates found in file" error rather than a false positive pass.
func TestInspector_IsSvid_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(path, []byte{}, 0600))

	i := X509Inspector{Filename: path, IsSvid: true}
	_, err := i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found in file",
		"--isSvid must error on empty file, not report conformance")
}

// TestInspector_IsSvid_PrivateKeyOnlyPEM verifies that --isSvid with a PEM file that
// contains only a private key (no CERTIFICATE block) returns a "failed to read certificates
// from file" error rather than a false positive pass.
func TestInspector_IsSvid_PrivateKeyOnlyPEM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	path := filepath.Join(t.TempDir(), "key-only.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))

	i := X509Inspector{Filename: path, IsSvid: true}
	_, err = i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read certificates from file",
		"--isSvid must error when file contains no CERTIFICATE blocks, not report conformance")
}

func TestInspector_IsSvid_Conformant(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, IsSvid: true}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Empty(t, output)
}

func TestInspector_IsSvid_NonConformant(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)
	path := writeCerts(t, caCert)

	i := X509Inspector{Filename: path, IsSvid: true}
	_, err = i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a well-formed X.509-SVID")
}

func TestIsSvid_CRLSign(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate key usage includes cRLSign (not allowed for leaf SVIDs)")
}

func TestIsSvid_MultipleViolations(t *testing.T) {
	// A CA cert has no URI SAN, IsCA=true, and keyCertSign — multiple violations.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)

	ok, reasons := checkIsSvid(caCert)
	assert.False(t, ok)
	assert.GreaterOrEqual(t, len(reasons), 2, "expected multiple violation reasons; got: %v", reasons)

	hasURIReason := false
	hasIsCAReason := false
	for _, r := range reasons {
		if strings.Contains(r, "no URI SAN") {
			hasURIReason = true
		}
		if strings.Contains(r, "IsCA=true") {
			hasIsCAReason = true
		}
	}
	assert.True(t, hasURIReason, "expected reason about missing URI SAN; got: %v", reasons)
	assert.True(t, hasIsCAReason, "expected reason about IsCA=true; got: %v", reasons)
}

func TestInspector_IsSvid_EvaluatesFirstCertOnly(t *testing.T) {
	// leaf cert (first) is conformant; caCert (second) is not.
	// --isSvid should pass because only the first cert is evaluated.
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")

	caKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca2 := testx509.NewCertificateAuthority(t, "CA2", testx509.WithSigner(caKey2))
	caCert2 := ca2.GenerateCaCertificate(t)

	path := writeCerts(t, leaf, caCert2)

	i := X509Inspector{Filename: path, IsSvid: true}
	output, err := i.Inspect()
	require.NoError(t, err, "expected pass: first cert is conformant; second cert is irrelevant")
	assert.Empty(t, output)
}

func TestInspector_Summary_SpiffeIDError_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "SPIFFE ID Error", "summary output should render error code when SPIFFE ID is malformed")
	assert.NotContains(t, output, "SPIFFE ID: ", "error case must not render normal SPIFFE ID line")
	assert.NotContains(t, output, "Trust Domain", "error case must not render Trust Domain")
}

func TestInspector_Summary_SpiffeIDError_OmittedWhenValid(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "SPIFFE ID Error", "valid SVID should not render error code in summary")
	assert.Contains(t, output, "spiffe://example.com/workload")
}

func TestInspector_Summary_SpiffeIDError_MultipleSpiffeIDs(t *testing.T) {
	// A cert with two valid SPIFFE URI SANs is ambiguous; certToInfo sets SpiffeIDError
	// to SpiffeIDErrorMultipleIDs. Verify the summary surfaces it.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: "ambiguous"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "SPIFFE ID Error", "ambiguous cert should surface error code in summary")
	assert.Contains(t, output, SpiffeIDErrorMultipleIDs)
}

func TestInspector_Summary_SpiffeIDErrorDetail_Present(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "SPIFFE ID Error Detail", "summary must render the detail line for INVALID_SPIFFE_URI")
	assert.Contains(t, output, "URI is not a valid SPIFFE ID", "summary detail must contain the stable fixed string")
	assert.Contains(t, output, "SPIFFE ID Library Error", "summary must render the raw library error line for INVALID_SPIFFE_URI")
}

func TestInspector_Summary_SpiffeIDErrorDetail_MultipleSpiffeIDs(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(88),
		Subject:               pkix.Name{CommonName: "ambiguous"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.Contains(t, output, "SPIFFE ID Error Detail", "summary must render detail line for MULTIPLE_SPIFFE_IDS")
	assert.Contains(t, output, "certificate contains multiple SPIFFE IDs",
		"summary detail must contain the hardcoded explanation string")
}

func TestInspector_Summary_SpiffeIDErrorDetail_OmittedWhenValid(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "SPIFFE ID Error Detail", "valid SVID should not render error detail in summary")
}

// TestInspector_Summary_MultipleSpiffeIDs_NoLibraryErrorLine verifies that the
// MULTIPLE_SPIFFE_IDS case never emits a "SPIFFE ID Library Error" line — that field
// is only set when there is an actual parse error (INVALID_SPIFFE_URI case).
func TestInspector_Summary_MultipleSpiffeIDs_NoLibraryErrorLine(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	u1, _ := url.Parse("spiffe://example.com/one")
	u2, _ := url.Parse("spiffe://example.com/two")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: "multi-id-no-lib-err"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{u1, u2},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	path := writeCerts(t, cert)

	i := X509Inspector{Filename: path, OutputFormat: "summary"}
	output, err := i.Inspect()
	require.NoError(t, err)

	assert.NotContains(t, output, "SPIFFE ID Library Error",
		"MULTIPLE_SPIFFE_IDS case must not emit a library error line — there is no parse error")
}

// TestInspector_JSON_SpiffeIDErrorDetail_DoesNotContainRawLibraryText verifies that
// the JSON spiffe_id_error_detail field never contains the raw go-spiffe library error
// text — only the stable fixed string — even when the library error would reference
// attacker-controlled URI content.
func TestInspector_JSON_SpiffeIDErrorDetail_DoesNotContainRawLibraryText(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	// Capture what the raw library error actually is so we can assert its absence.
	info := certToInfo(cert)
	require.NotEmpty(t, info.spiffeIDLibraryError)
	rawLibErr := info.spiffeIDLibraryError

	i := X509Inspector{Filename: path, OutputFormat: "json"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.NotEqual(t, rawLibErr, certs[0].SpiffeIDErrorDetail,
		"JSON SpiffeIDErrorDetail must be the fixed string, not the raw library error text")
	assert.NotContains(t, output, rawLibErr,
		"raw go-spiffe library error text must not appear anywhere in JSON output")
}

// TestInspector_YAML_SpiffeIDErrorDetail_DoesNotContainRawLibraryText mirrors the JSON
// version above for YAML output.
func TestInspector_YAML_SpiffeIDErrorDetail_DoesNotContainRawLibraryText(t *testing.T) {
	cert := newCertWithMalformedSpiffeURI(t)
	path := writeCerts(t, cert)

	info := certToInfo(cert)
	require.NotEmpty(t, info.spiffeIDLibraryError)
	rawLibErr := info.spiffeIDLibraryError

	i := X509Inspector{Filename: path, OutputFormat: "yaml"}
	output, err := i.Inspect()
	require.NoError(t, err)

	var certs []CertificateInfo
	require.NoError(t, yaml.Unmarshal([]byte(output), &certs))
	require.Len(t, certs, 1)
	assert.NotEqual(t, rawLibErr, certs[0].SpiffeIDErrorDetail,
		"YAML SpiffeIDErrorDetail must be the fixed string, not the raw library error text")
	assert.NotContains(t, output, rawLibErr,
		"raw go-spiffe library error text must not appear anywhere in YAML output")
}

func TestInspector_Color_YAML(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{
		Filename:      path,
		OutputFormat:  "yaml",
		OutputOptions: X509InspectOutputOptions{Color: true},
	}
	_, err := i.Inspect()
	require.NoError(t, err)
}

func TestInspector_Color_Summary(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := &X509Inspector{
		Filename:      path,
		OutputFormat:  "summary",
		OutputOptions: X509InspectOutputOptions{Color: true},
	}
	output, err := i.Inspect()
	require.NoError(t, err)
	assert.Contains(t, output, "spiffe://example.com/workload")
}

// TestInspector_Color_PlainTextFormats verifies that chain and tree bypass chroma entirely when
// Color=true, while json still passes through chroma (its output must differ from raw converter output).
func TestInspector_Color_PlainTextFormats(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	// chain: Color=true output must equal raw ConvertCertsToChain output.
	t.Run("chain bypasses chroma", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates(path)
		require.NoError(t, err)
		raw, err := ConvertCertsToChain(certs, X509ConvertOptions{})
		require.NoError(t, err)

		colorOutput, err := (&X509Inspector{
			Filename:      path,
			OutputFormat:  "chain",
			OutputOptions: X509InspectOutputOptions{Color: true},
		}).Inspect()
		require.NoError(t, err)
		assert.Equal(t, raw, colorOutput, "chain with Color=true must not pass through chroma")
		assert.NotContains(t, colorOutput, "\x1b",
			"--color is a no-op for chain format: chain bypasses chroma and must never emit ANSI escape sequences")
	})

	// tree: Color=true output must equal raw ConvertCertsToTree output.
	t.Run("tree bypasses chroma", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates(path)
		require.NoError(t, err)
		raw, err := ConvertCertsToTree(certs, X509ConvertOptions{Chain: X509ChainOptions{TreeFields: []string{"subject"}}})
		require.NoError(t, err)

		colorOutput, err := (&X509Inspector{
			Filename:      path,
			OutputFormat:  "tree",
			TreeFields:    "subject",
			OutputOptions: X509InspectOutputOptions{Color: true},
		}).Inspect()
		require.NoError(t, err)
		assert.Equal(t, raw, colorOutput, "tree with Color=true must not pass through chroma")
		assert.NotContains(t, colorOutput, "\x1b",
			"--color is a no-op for tree format: tree bypasses chroma and must never emit ANSI escape sequences")
	})

	// json: Color=true output must differ from raw ConvertCertsToJson output (chroma added ANSI).
	t.Run("json still uses chroma", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates(path)
		require.NoError(t, err)
		raw, err := ConvertCertsToJson(certs, X509ConvertOptions{})
		require.NoError(t, err)

		colorOutput, err := (&X509Inspector{
			Filename:      path,
			OutputFormat:  "json",
			OutputOptions: X509InspectOutputOptions{Color: true},
		}).Inspect()
		require.NoError(t, err)
		assert.NotEqual(t, raw, colorOutput, "json with Color=true must pass through chroma (ANSI escapes added)")
	})
}

// writeFixtureIfNeeded writes certs to path only when the existing file fails the validity check.
// ECDSA signing in Go 1.24+ still draws from crypto/rand, so calling x509.CreateCertificate
// twice with the same key produces different DER bytes. Skipping writes when the on-disk
// fixture is already structurally valid makes TestGenerateFixtures -update idempotent:
// the first run generates the file, subsequent runs leave it unchanged.
func writeFixtureIfNeeded(t *testing.T, path string, certs []*x509.Certificate, valid func([]*x509.Certificate) bool) {
	t.Helper()
	if existing, err := pemutil.LoadCertificates(path); err == nil && valid(existing) {
		return
	}
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates(certs), 0600))
}

// TestWriteFixtureIfNeeded verifies the idempotency contract of writeFixtureIfNeeded:
// it writes on the first call when no valid file exists, skips on subsequent calls when
// the on-disk file satisfies the validity check, and overwrites when validity fails.
func TestWriteFixtureIfNeeded(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	leafTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-leaf"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leafCert := testx509.CreateCertificate(t, &leafTemplate, &issuer, leafKey.Public(), caKey)

	isLeafWithSPIFFE := func(c []*x509.Certificate) bool {
		return len(c) == 1 && !c[0].IsCA && len(c[0].URIs) == 1
	}
	isCA := func(c []*x509.Certificate) bool {
		return len(c) == 1 && c[0].IsCA
	}

	t.Run("creates file when it does not exist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fixture.pem")
		writeFixtureIfNeeded(t, path, []*x509.Certificate{leafCert}, isLeafWithSPIFFE)

		data, err := os.ReadFile(path) //nolint:gosec // path is a t.TempDir() path, not user input
		require.NoError(t, err)
		require.NotEmpty(t, data)

		loaded, err := pemutil.LoadCertificates(path)
		require.NoError(t, err)
		require.Len(t, loaded, 1)
		assert.False(t, loaded[0].IsCA)
	})

	t.Run("skips write when existing file satisfies validity — bytes are unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fixture.pem")
		// First call: creates the file.
		writeFixtureIfNeeded(t, path, []*x509.Certificate{leafCert}, isLeafWithSPIFFE)
		before, err := os.ReadFile(path) //nolint:gosec // path is a t.TempDir() path, not user input
		require.NoError(t, err)

		// Second call with a freshly-generated cert but the same validity predicate.
		// Because ECDSA signing is non-deterministic, the new cert would produce
		// different DER bytes — but writeFixtureIfNeeded must skip the write entirely.
		leafKey2, err2 := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err2)
		leafCert2 := testx509.CreateCertificate(t, &leafTemplate, &issuer, leafKey2.Public(), caKey)

		writeFixtureIfNeeded(t, path, []*x509.Certificate{leafCert2}, isLeafWithSPIFFE)
		after, err := os.ReadFile(path) //nolint:gosec // path is a t.TempDir() path, not user input
		require.NoError(t, err)

		require.Equal(t, before, after, "writeFixtureIfNeeded must not overwrite a file that passes the validity check")
	})

	t.Run("overwrites when existing file fails validity", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "fixture.pem")
		// Seed the file with a leaf cert.
		require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificates([]*x509.Certificate{leafCert}), 0600))
		before, err := os.ReadFile(path) //nolint:gosec // path is a t.TempDir() path, not user input
		require.NoError(t, err)

		// Validity predicate requires IsCA=true — the leaf cert fails.
		caCert := ca.GenerateCaCertificate(t,
			testx509.WithValidityPeriod(testx509.ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
			testx509.WithSerialNumber(*big.NewInt(99)),
		)
		writeFixtureIfNeeded(t, path, []*x509.Certificate{caCert}, isCA)

		after, err := os.ReadFile(path) //nolint:gosec // path is a t.TempDir() path, not user input
		require.NoError(t, err)
		require.NotEqual(t, before, after, "writeFixtureIfNeeded must overwrite when the existing file fails validity")

		loaded, err := pemutil.LoadCertificates(path)
		require.NoError(t, err)
		require.Len(t, loaded, 1)
		assert.True(t, loaded[0].IsCA)
	})
}

// TestGenerateFixtures writes static PEM certificate fixtures to testdata/.
// Run with -update to regenerate: go test ./internal/x509inspect/ -run TestGenerateFixtures -update
//
// Each fixture is written only when the existing file does not already satisfy the structural
// requirements. This makes consecutive -update runs produce byte-identical files even though
// ECDSA signatures are non-deterministic across program invocations.
func TestGenerateFixtures(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate PEM fixtures")
	}

	require.NoError(t, os.MkdirAll("testdata", 0750))

	notBefore := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)

	caKey := fixtureCAKey
	ca := testx509.NewCertificateAuthority(t, "Test Root CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t,
		testx509.WithValidityPeriod(testx509.ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
		testx509.WithSerialNumber(*big.NewInt(1)),
	)

	leafKey := fixtureLeafKey
	spiffeURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	issuer := ca.GetIssuerTemplate(t)
	leafTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test-workload"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		AuthorityKeyId:        issuer.SubjectKeyId,
	}
	leafCert := testx509.CreateCertificate(t, &leafTemplate, &issuer, leafKey.Public(), caKey)

	writeFixtureIfNeeded(t, "testdata/leaf-svid.pem", []*x509.Certificate{leafCert}, func(c []*x509.Certificate) bool {
		return len(c) == 1 && !c[0].IsCA && len(c[0].URIs) == 1 && c[0].URIs[0].String() == "spiffe://example.com/workload"
	})
	writeFixtureIfNeeded(t, "testdata/multi-cert.pem", []*x509.Certificate{leafCert, caCert}, func(c []*x509.Certificate) bool {
		return len(c) == 2 && !c[0].IsCA && len(c[0].URIs) == 1 && c[1].IsCA
	})
	writeFixtureIfNeeded(t, "testdata/ca-only.pem", []*x509.Certificate{caCert}, func(c []*x509.Certificate) bool {
		return len(c) == 1 && c[0].IsCA && len(c[0].URIs) == 0
	})

	// chain-3-deep.pem: leaf (SPIFFE) + intermediate CA + root CA, leaf-first order.
	intermediateKey := fixtureIntermediateKey
	intermediateCert := ca.GenerateCaCertificate(t,
		testx509.WithPublicKey(intermediateKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Test Intermediate CA"}),
		testx509.WithValidityPeriod(testx509.ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
		testx509.WithSerialNumber(*big.NewInt(2)),
	)

	deepLeafTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(43),
		Subject:               pkix.Name{CommonName: "test-workload"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	deepLeafCert := testx509.CreateCertificate(t, &deepLeafTemplate, intermediateCert, leafKey.Public(), intermediateKey)

	writeFixtureIfNeeded(t, "testdata/chain-3-deep.pem", []*x509.Certificate{deepLeafCert, intermediateCert, caCert}, func(c []*x509.Certificate) bool {
		return len(c) == 3 &&
			!c[0].IsCA && len(c[0].URIs) == 1 && c[0].URIs[0].String() == "spiffe://example.com/workload" &&
			c[1].IsCA && c[1].Subject.CommonName == "Test Intermediate CA" && !isSelfSigned(c[1]) &&
			c[2].IsCA && c[2].Subject.CommonName == "Test Root CA" && isSelfSigned(c[2])
	})

	// chain-with-extras.pem: leaf + live intermediate + 2 stale intermediates (leaf-first order).
	// chain-with-extras.roots.pem: root CA (same cert as in chain-3-deep.pem).
	staleIntAKey := fixtureStaleIntermediateAKey
	staleIntACert := ca.GenerateCaCertificate(t,
		testx509.WithPublicKey(staleIntAKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Test Stale Intermediate A"}),
		testx509.WithValidityPeriod(testx509.ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
		testx509.WithSerialNumber(*big.NewInt(3)),
	)

	staleIntBKey := fixtureStaleIntermediateBKey
	staleIntBCert := ca.GenerateCaCertificate(t,
		testx509.WithPublicKey(staleIntBKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Test Stale Intermediate B"}),
		testx509.WithValidityPeriod(testx509.ValidityPeriod{NotBefore: notBefore, NotAfter: notAfter}),
		testx509.WithSerialNumber(*big.NewInt(4)),
	)

	writeFixtureIfNeeded(t, "testdata/chain-with-extras.pem", []*x509.Certificate{deepLeafCert, intermediateCert, staleIntACert, staleIntBCert}, func(c []*x509.Certificate) bool {
		return len(c) == 4 &&
			!c[0].IsCA && len(c[0].URIs) == 1 && c[0].URIs[0].String() == "spiffe://example.com/workload" &&
			c[1].IsCA && c[1].Subject.CommonName == "Test Intermediate CA" && !isSelfSigned(c[1]) &&
			c[2].IsCA && c[2].Subject.CommonName == "Test Stale Intermediate A" &&
			c[3].IsCA && c[3].Subject.CommonName == "Test Stale Intermediate B"
	})
	writeFixtureIfNeeded(t, "testdata/chain-with-extras.roots.pem", []*x509.Certificate{caCert}, func(c []*x509.Certificate) bool {
		return len(c) == 1 && c[0].IsCA && c[0].Subject.CommonName == "Test Root CA" && isSelfSigned(c[0])
	})
}

// readOrUpdateGolden returns the content of the golden file at path.
// When -update is set, it writes actual to path first.
func readOrUpdateGolden(t *testing.T, path string, actual string) string {
	t.Helper()
	if *update {
		require.NoError(t, os.WriteFile(path, []byte(actual), 0600))
		return actual
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is always a testdata/ relative path constructed in this file
	require.NoError(t, err)
	return string(data)
}

// TestStaticPEMFixtures validates the structure of the checked-in PEM fixtures.
// These are canary tests: they fail immediately if a fixture is accidentally
// regenerated with wrong parameters or otherwise corrupted.
func TestStaticPEMFixtures(t *testing.T) {
	t.Run("leaf-svid.pem: single conformant SVID", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates("testdata/leaf-svid.pem")
		require.NoError(t, err)
		require.Len(t, certs, 1, "leaf-svid.pem must contain exactly one certificate")

		cert := certs[0]
		require.Len(t, cert.URIs, 1, "leaf must have exactly one URI SAN")
		assert.Equal(t, "spiffe://example.com/workload", cert.URIs[0].String())
		assert.False(t, cert.IsCA)
		assert.True(t, cert.BasicConstraintsValid)

		ok, reasons := checkIsSvid(cert)
		assert.True(t, ok, "leaf-svid.pem must be a conformant X.509-SVID; violations: %v", reasons)
	})

	t.Run("multi-cert.pem: two certs, leaf first then CA", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates("testdata/multi-cert.pem")
		require.NoError(t, err)
		require.Len(t, certs, 2, "multi-cert.pem must contain exactly two certificates")

		leaf, ca := certs[0], certs[1]

		assert.False(t, leaf.IsCA, "first cert must be the leaf (IsCA=false)")
		require.Len(t, leaf.URIs, 1)
		assert.Equal(t, "spiffe://example.com/workload", leaf.URIs[0].String())

		assert.True(t, ca.IsCA, "second cert must be the CA (IsCA=true)")
		assert.Empty(t, ca.URIs, "CA cert must have no URI SANs")
	})

	t.Run("ca-only.pem: single CA cert with no SPIFFE fields", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates("testdata/ca-only.pem")
		require.NoError(t, err)
		require.Len(t, certs, 1, "ca-only.pem must contain exactly one certificate")

		cert := certs[0]
		assert.True(t, cert.IsCA)
		assert.Empty(t, cert.URIs)
	})

	t.Run("chain-3-deep.pem: leaf + intermediate CA + root CA, leaf-first order", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates("testdata/chain-3-deep.pem")
		require.NoError(t, err)
		require.Len(t, certs, 3, "chain-3-deep.pem must contain exactly three certificates")

		leaf, intermediate, root := certs[0], certs[1], certs[2]

		// Leaf: non-CA with SPIFFE URI SAN.
		assert.False(t, leaf.IsCA, "first cert must be the leaf (IsCA=false)")
		require.Len(t, leaf.URIs, 1, "leaf must have exactly one URI SAN")
		assert.Equal(t, "spiffe://example.com/workload", leaf.URIs[0].String())

		// Intermediate: CA cert with expected CN.
		assert.True(t, intermediate.IsCA, "second cert must be an intermediate CA (IsCA=true)")
		assert.Equal(t, "Test Intermediate CA", intermediate.Subject.CommonName)
		assert.False(t, isSelfSigned(intermediate), "intermediate CA must not be self-signed")

		// Root: CA cert with expected CN, and self-signed.
		assert.True(t, root.IsCA, "third cert must be the root CA (IsCA=true)")
		assert.Equal(t, "Test Root CA", root.Subject.CommonName)
		assert.True(t, isSelfSigned(root), "root CA must be self-signed")
	})

	t.Run("chain-with-extras.pem + chain-with-extras.roots.pem: extras fixture structure", func(t *testing.T) {
		certs, err := pemutil.LoadCertificates("testdata/chain-with-extras.pem")
		require.NoError(t, err)
		require.Len(t, certs, 4, "chain-with-extras.pem must contain exactly four certificates")

		leaf, liveInt, staleA, staleB := certs[0], certs[1], certs[2], certs[3]

		// Leaf: non-CA with SPIFFE URI SAN.
		assert.False(t, leaf.IsCA, "first cert must be the leaf (IsCA=false)")
		require.Len(t, leaf.URIs, 1, "leaf must have exactly one URI SAN")
		assert.Equal(t, "spiffe://example.com/workload", leaf.URIs[0].String())

		// Live intermediate.
		assert.True(t, liveInt.IsCA, "second cert must be live intermediate (IsCA=true)")
		assert.Equal(t, "Test Intermediate CA", liveInt.Subject.CommonName)
		assert.False(t, isSelfSigned(liveInt), "live intermediate must not be self-signed")

		// Stale intermediates.
		assert.True(t, staleA.IsCA, "third cert must be stale intermediate A (IsCA=true)")
		assert.Equal(t, "Test Stale Intermediate A", staleA.Subject.CommonName)
		assert.False(t, isSelfSigned(staleA), "stale intermediate A must not be self-signed")

		assert.True(t, staleB.IsCA, "fourth cert must be stale intermediate B (IsCA=true)")
		assert.Equal(t, "Test Stale Intermediate B", staleB.Subject.CommonName)
		assert.False(t, isSelfSigned(staleB), "stale intermediate B must not be self-signed")

		// Roots file must contain exactly one cert: same root as chain-3-deep.pem.
		roots, err := pemutil.LoadCertificates("testdata/chain-with-extras.roots.pem")
		require.NoError(t, err)
		require.Len(t, roots, 1, "chain-with-extras.roots.pem must contain exactly one certificate")
		root := roots[0]
		assert.True(t, root.IsCA, "root must be a CA cert")
		assert.Equal(t, "Test Root CA", root.Subject.CommonName)
		assert.True(t, isSelfSigned(root), "root must be self-signed")

		// Same root key/cert as chain-3-deep.pem.
		deepCerts, err := pemutil.LoadCertificates("testdata/chain-3-deep.pem")
		require.NoError(t, err)
		deepRoot := deepCerts[2]
		assert.Equal(t, certFingerprint(deepRoot), certFingerprint(root), "root in chain-with-extras.roots.pem must match root in chain-3-deep.pem")

		// The extras fixture must verify: leaf chains to root via live intermediate.
		rootPool := x509.NewCertPool()
		rootPool.AddCert(root)
		intPool := x509.NewCertPool()
		intPool.AddCert(liveInt)
		intPool.AddCert(staleA)
		intPool.AddCert(staleB)
		_, err = leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intPool})
		assert.NoError(t, err, "leaf must verify against root via intermediates pool")
	})
}

// TestInspector_IsSvid_StaticFixtures exercises the --isSvid flag against committed fixtures.
func TestInspector_IsSvid_StaticFixtures(t *testing.T) {
	t.Run("leaf-svid.pem passes --isSvid", func(t *testing.T) {
		i := X509Inspector{Filename: "testdata/leaf-svid.pem", IsSvid: true}
		output, err := i.Inspect()
		require.NoError(t, err)
		assert.Empty(t, output)
	})

	t.Run("ca-only.pem fails --isSvid", func(t *testing.T) {
		i := X509Inspector{Filename: "testdata/ca-only.pem", IsSvid: true}
		_, err := i.Inspect()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a well-formed X.509-SVID")
	})

	t.Run("multi-cert.pem passes --isSvid (evaluates first cert only)", func(t *testing.T) {
		i := X509Inspector{Filename: "testdata/multi-cert.pem", IsSvid: true}
		output, err := i.Inspect()
		require.NoError(t, err, "leaf is conformant; CA as second cert must not be evaluated")
		assert.Empty(t, output)
	})
}

// TestIsSvid_BasicConstraintsNotValid covers the §4.1 branch where the
// BasicConstraints extension is absent (BasicConstraintsValid == false).
func TestIsSvid_BasicConstraintsNotValid(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "no-basic-constraints"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// BasicConstraintsValid deliberately omitted — extension will not be present.
		IsCA: false,
		URIs: []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	require.False(t, cert.BasicConstraintsValid, "precondition: BasicConstraints extension must be absent")

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	assert.Contains(t, reasons, "certificate does not have a valid BasicConstraints extension")
}

// TestIsSvid_InvalidValidityPeriod covers the §4.5 branch where NotBefore == NotAfter.
func TestIsSvid_InvalidValidityPeriod(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "zero-validity"},
		NotBefore:             ts,
		NotAfter:              ts, // equal to NotBefore — not a valid period
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "invalid validity period") {
			found = true
		}
	}
	assert.True(t, found, "expected a reason about invalid validity period; got: %v", reasons)
}

// TestInspector_IsSvid_BasicConstraintsNotValid_ErrorMessage verifies that the error returned by
// Inspect() when IsSvid=true and the cert is missing a valid BasicConstraints extension contains
// the updated wording "does not have a valid BasicConstraints extension". This is the integration-
// level counterpart to TestIsSvid_BasicConstraintsNotValid, which tests checkIsSvid directly.
func TestInspector_IsSvid_BasicConstraintsNotValid_ErrorMessage(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/workload")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "no-basic-constraints"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// BasicConstraintsValid deliberately omitted — extension will not be present.
		IsCA: false,
		URIs: []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)
	require.False(t, cert.BasicConstraintsValid, "precondition: BasicConstraints extension must be absent")

	path := writeCerts(t, cert)
	i := X509Inspector{Filename: path, IsSvid: true}
	_, err = i.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not have a valid BasicConstraints extension",
		"error message should use updated wording that covers both absent and invalid extensions")
}

// TestInspector_IsSvid_Conformant_IgnoresFormat verifies that when IsSvid=true and the cert
// is conformant, Inspect() returns ("", nil) regardless of what OutputFormat is set.
// This is a regression guard: the early-return at inspector.go:57 must fire before the
// FormatMap lookup, so format flags should have no effect on success output.
func TestInspector_IsSvid_Conformant_IgnoresFormat(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	for _, format := range []string{"json", "yaml", "summary", ""} {
		format := format
		t.Run("format="+format, func(t *testing.T) {
			i := X509Inspector{Filename: path, IsSvid: true, OutputFormat: format}
			output, err := i.Inspect()
			require.NoError(t, err)
			assert.Empty(t, output, "--isSvid success must produce no output regardless of OutputFormat")
		})
	}
}

// TestInspector_IsSvid_SuccessReturnsExactlyEmptyString is a regression guard for the review
// comment that flagged Inspect() returning "certificate is a well-formed X.509-SVID\n" on
// conformant input. Both x509inspect and jwtinspect must return ("", nil) on --isSvid success
// so callers rely solely on the nil error as the conformance signal (exit-code gate pattern).
// Mirrors the assertion style at internal/jwtinspect/inspector_test.go:37.
func TestInspector_IsSvid_SuccessReturnsExactlyEmptyString(t *testing.T) {
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/workload")
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, IsSvid: true}
	output, err := i.Inspect()
	require.NoError(t, err)
	require.Equal(t, "", output, "IsSvid success must return exactly empty string, not a success message")
}

// TestInspector_IsSvid_NonConformant_ErrorContainsViolationNames verifies that when IsSvid=true
// and the cert is non-conformant, the error from Inspect() includes the specific violation names.
// The checkIsSvid unit tests verify reasons are collected correctly; this test verifies they
// surface through the Inspect() error string so callers/scripts can grep for them.
func TestInspector_IsSvid_NonConformant_ErrorContainsViolationNames(t *testing.T) {
	tests := []struct {
		name           string
		buildCert      func(t *testing.T) *x509.Certificate
		wantErrSubstr  string
	}{
		{
			name: "no URI SAN",
			buildCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				issuer := ca.GetIssuerTemplate(t)
				tmpl := x509.Certificate{
					SerialNumber:          big.NewInt(1),
					Subject:               pkix.Name{CommonName: "no-uri-san"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					BasicConstraintsValid: true,
					IsCA:                  false,
				}
				return testx509.CreateCertificate(t, &tmpl, &issuer, leafKey.Public(), caKey)
			},
			wantErrSubstr: "no URI SAN",
		},
		{
			name: "missing digitalSignature",
			buildCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				spiffeURI, _ := url.Parse("spiffe://example.com/test")
				issuer := ca.GetIssuerTemplate(t)
				tmpl := x509.Certificate{
					SerialNumber:          big.NewInt(2),
					Subject:               pkix.Name{CommonName: "no-digsig"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageContentCommitment, // no digitalSignature
					BasicConstraintsValid: true,
					IsCA:                  false,
					URIs:                  []*url.URL{spiffeURI},
				}
				return testx509.CreateCertificate(t, &tmpl, &issuer, leafKey.Public(), caKey)
			},
			wantErrSubstr: "digitalSignature",
		},
		{
			name: "keyCertSign present",
			buildCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				spiffeURI, _ := url.Parse("spiffe://example.com/test")
				issuer := ca.GetIssuerTemplate(t)
				tmpl := x509.Certificate{
					SerialNumber:          big.NewInt(3),
					Subject:               pkix.Name{CommonName: "has-certsign"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  false,
					URIs:                  []*url.URL{spiffeURI},
				}
				return testx509.CreateCertificate(t, &tmpl, &issuer, leafKey.Public(), caKey)
			},
			wantErrSubstr: "keyCertSign",
		},
		{
			name: "disallowed EKU codeSigning",
			buildCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
				leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				spiffeURI, _ := url.Parse("spiffe://example.com/test")
				issuer := ca.GetIssuerTemplate(t)
				tmpl := x509.Certificate{
					SerialNumber:          big.NewInt(4),
					Subject:               pkix.Name{CommonName: "bad-eku"},
					NotBefore:             time.Now().Add(-time.Hour),
					NotAfter:              time.Now().Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature,
					ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
					BasicConstraintsValid: true,
					IsCA:                  false,
					URIs:                  []*url.URL{spiffeURI},
				}
				return testx509.CreateCertificate(t, &tmpl, &issuer, leafKey.Public(), caKey)
			},
			wantErrSubstr: "codeSigning",
		},
		{
			name: "unknown EKU OID",
			buildCert: func(t *testing.T) *x509.Certificate {
				t.Helper()
				return newCertWithUnknownEKUOID(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7})
			},
			wantErrSubstr: "disallowed unknown OID",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.buildCert(t)
			path := writeCerts(t, cert)
			i := X509Inspector{Filename: path, IsSvid: true}
			_, err := i.Inspect()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a well-formed X.509-SVID")
			assert.Contains(t, err.Error(), tt.wantErrSubstr,
				"error must name the specific violation so scripts can grep for it")
		})
	}
}

// TestIsSvid_NoEKU verifies that a cert with no EKU extension at all is conformant.
// §4.4 says EKU is optional; an absent EKU imposes no restrictions.
func TestIsSvid_NoEKU(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "no-eku"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		// ExtKeyUsage deliberately omitted — the extension will not be present.
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.True(t, ok, "absent EKU must be conformant; got reasons: %v", reasons)
	assert.Empty(t, reasons)
}

// TestIsSvid_ClientAuthOnly verifies that a cert with only clientAuth EKU is conformant.
func TestIsSvid_ClientAuthOnly(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "client-auth-only"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.True(t, ok, "clientAuth-only EKU must be conformant; got reasons: %v", reasons)
	assert.Empty(t, reasons)
}

// TestIsSvid_ServerAuthOnly verifies that a cert with only serverAuth EKU is conformant.
func TestIsSvid_ServerAuthOnly(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "server-auth-only"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.True(t, ok, "serverAuth-only EKU must be conformant; got reasons: %v", reasons)
	assert.Empty(t, reasons)
}

// TestIsSvid_ReversedValidityPeriod covers §4.5 where NotBefore is strictly after NotAfter.
// Complements TestIsSvid_InvalidValidityPeriod (which tests the equal case).
func TestIsSvid_ReversedValidityPeriod(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	issuer := ca.GetIssuerTemplate(t)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "reversed-validity"},
		NotBefore:             time.Now().Add(24 * time.Hour), // after NotAfter
		NotAfter:              time.Now().Add(-time.Hour),     // before NotBefore
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	cert := testx509.CreateCertificate(t, &template, &issuer, leafKey.Public(), caKey)

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "invalid validity period") {
			found = true
		}
	}
	assert.True(t, found, "expected a reason about invalid validity period; got: %v", reasons)
}

// TestCheckIsSvid_DisallowedEKUs_ProduceHumanReadableNames verifies that every
// disallowed EKU value that is known to extKeyUsageNames produces a human-readable
// name (not "unknown(N)") in the checkIsSvid error message.
func TestCheckIsSvid_DisallowedEKUs_ProduceHumanReadableNames(t *testing.T) {
	// serverAuth and clientAuth are the only allowed EKUs — skip them.
	allowedEKUs := map[x509.ExtKeyUsage]bool{
		x509.ExtKeyUsageServerAuth: true,
		x509.ExtKeyUsageClientAuth: true,
	}

	for eku, wantName := range extKeyUsageNames {
		if allowedEKUs[eku] {
			continue
		}
		eku, wantName := eku, wantName
		t.Run(wantName, func(t *testing.T) {
			caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			ca := testx509.NewCertificateAuthority(t, "CA", testx509.WithSigner(caKey))
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)

			spiffeURI, _ := url.Parse("spiffe://example.com/test")
			issuer := ca.GetIssuerTemplate(t)
			tmpl := x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "eku-test"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{eku},
				BasicConstraintsValid: true,
				IsCA:                  false,
				URIs:                  []*url.URL{spiffeURI},
			}
			cert := testx509.CreateCertificate(t, &tmpl, &issuer, leafKey.Public(), caKey)

			ok, reasons := checkIsSvid(cert)
			assert.False(t, ok, "EKU %v (%q) should be disallowed", eku, wantName)
			wantReason := "extended key usage contains disallowed value: " + wantName
			assert.Contains(t, reasons, wantReason,
				"checkIsSvid must name the EKU as %q, not as \"unknown(N)\"", wantName)
		})
	}
}

// TestCheckIsSvid_UnknownNumericEKU_FallsBackToUnknownN verifies the unknown(N) fallback
// for an x509.ExtKeyUsage integer value that is not present in extKeyUsageNames.
// This path would be hit if Go's standard library adds a new EKU constant before we
// update extKeyUsageNames.
func TestCheckIsSvid_UnknownNumericEKU_FallsBackToUnknownN(t *testing.T) {
	// Construct a *x509.Certificate directly — we only need checkIsSvid to read the
	// parsed fields, so we do not need a DER-encoded cert signed by a CA.
	spiffeURI, _ := url.Parse("spiffe://example.com/test")
	syntheticEKU := x509.ExtKeyUsage(9999)
	cert := &x509.Certificate{
		URIs:                  []*url.URL{spiffeURI},
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{syntheticEKU},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	_, ok := extKeyUsageNames[syntheticEKU]
	require.False(t, ok, "precondition: EKU 9999 must not be in extKeyUsageNames")

	ok, reasons := checkIsSvid(cert)
	assert.False(t, ok, "synthetic EKU 9999 should be disallowed")
	var found bool
	for _, r := range reasons {
		if strings.Contains(r, "unknown(9999)") {
			found = true
			break
		}
	}
	assert.True(t, found, "unknown EKU must produce \"unknown(N)\" fallback; got reasons: %v", reasons)
}

// TestConvertCertsToChain_BundleCertsInMemory is a converter-layer regression guard.
// X509Inspector.Inspect() loads --bundle from disk then passes []*x509.Certificate to
// the converter. This test exercises the converter directly with an in-memory slice to
// confirm that the two ingestion paths (file-loaded vs in-memory) are equivalent: a bug
// affecting in-memory BundleCerts but not file loading would only be caught here.
func TestConvertCertsToChain_BundleCertsInMemory(t *testing.T) {
	certs, err := pemutil.LoadCertificates("testdata/chain-with-extras.pem")
	require.NoError(t, err)
	rootCerts, err := pemutil.LoadCertificates("testdata/chain-with-extras.roots.pem")
	require.NoError(t, err)
	actual, err := ConvertCertsToChain(certs, X509ConvertOptions{Chain: X509ChainOptions{BundleCerts: rootCerts}})
	require.NoError(t, err)
	assert.Contains(t, actual, "Test Root CA", "root from in-memory BundleCerts must appear in chain output")
	assert.Contains(t, actual, "[spiffe://example.com/workload]", "leaf must carry SPIFFE ID bracket")
}

// TestGoldenFiles asserts full rendered output for each PEM fixture matches the committed golden files.
// Run with -update to regenerate golden files: go test ./internal/x509inspect/ -run TestGoldenFiles -update
func TestGoldenFiles(t *testing.T) {
	goldenTime := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)

	type row struct {
		name         string
		pemPath      string
		format       string
		goldenSuffix string // default: "."+format; overrides when golden file name differs from format
		bundle       string
		shortestPath bool
		treeFields   string
		outputOpts   X509InspectOutputOptions
		// useSummary causes convertCertsToSummary(goldenTime) to be used instead of Inspect().
		useSummary bool
		// comparison controls the equality assertion: "json", "yaml", or "" (plain Equal).
		comparison  string
		extraChecks func(t *testing.T, actual string)
	}

	rows := []row{
		// ---- leaf-svid.pem ----
		{name: "leaf-svid.pem/json", pemPath: "testdata/leaf-svid.pem", format: "json", comparison: "json"},
		{name: "leaf-svid.pem/yaml", pemPath: "testdata/leaf-svid.pem", format: "yaml", comparison: "yaml"},
		{name: "leaf-svid.pem/summary", pemPath: "testdata/leaf-svid.pem", format: "summary", useSummary: true},
		// ---- multi-cert.pem ----
		{name: "multi-cert.pem/json", pemPath: "testdata/multi-cert.pem", format: "json", comparison: "json"},
		{name: "multi-cert.pem/yaml", pemPath: "testdata/multi-cert.pem", format: "yaml", comparison: "yaml"},
		{name: "multi-cert.pem/summary", pemPath: "testdata/multi-cert.pem", format: "summary", useSummary: true},
		// ---- ca-only.pem ----
		{name: "ca-only.pem/json", pemPath: "testdata/ca-only.pem", format: "json", comparison: "json"},
		{name: "ca-only.pem/yaml", pemPath: "testdata/ca-only.pem", format: "yaml", comparison: "yaml"},
		{name: "ca-only.pem/summary", pemPath: "testdata/ca-only.pem", format: "summary", useSummary: true},
		// ---- chain-3-deep.pem ----
		{
			name:    "chain-3-deep.pem/chain",
			pemPath: "testdata/chain-3-deep.pem",
			format:  "chain",
			extraChecks: func(t *testing.T, actual string) {
				lines := strings.Split(strings.TrimRight(actual, "\n"), "\n")
				require.Len(t, lines, 3, "3-cert chain must produce 3 lines")
				assert.False(t, strings.HasPrefix(lines[0], " "), "root must have no indent")
				assert.True(t, strings.HasPrefix(lines[1], "  "), "intermediate must have 2-space indent")
				assert.True(t, strings.HasPrefix(lines[2], "    "), "leaf must have 4-space indent")
				assert.Contains(t, lines[2], "  [spiffe://example.com/workload]", "leaf must carry SPIFFE ID bracket with two leading spaces")
			},
		},
		{
			name:       "chain-3-deep.pem/tree",
			pemPath:    "testdata/chain-3-deep.pem",
			format:     "tree",
			outputOpts: X509InspectOutputOptions{TimeZone: "UTC"},
			extraChecks: func(t *testing.T, actual string) {
				assert.Contains(t, actual, "└─")
				assert.Contains(t, actual, "Test Root CA")
				assert.Contains(t, actual, "Test Intermediate CA")
				assert.Contains(t, actual, "test-workload")
			},
		},
		{
			name:         "chain-3-deep.pem/tree.full",
			pemPath:      "testdata/chain-3-deep.pem",
			format:       "tree",
			goldenSuffix: ".tree.full",
			treeFields:   "subject,issuer,spiffe-id,serial,not-after,key-algorithm,sha256-fp",
			outputOpts:   X509InspectOutputOptions{TimeZone: "UTC"},
			extraChecks: func(t *testing.T, actual string) {
				const allFields = "subject,issuer,spiffe-id,serial,not-after,key-algorithm,sha256-fp"
				for _, f := range strings.Split(allFields, ",")[1:] {
					assert.Contains(t, actual, f+":", "full tree must contain field label %q", f)
				}
				assert.Contains(t, actual, "spiffe-id: spiffe://example.com/workload", "leaf spiffe-id must appear")
			},
		},
		// ---- chain-with-extras.pem ----
		{
			name:    "chain-with-extras.pem/chain",
			pemPath: "testdata/chain-with-extras.pem",
			format:  "chain",
			bundle:  "testdata/chain-with-extras.roots.pem",
			extraChecks: func(t *testing.T, actual string) {
				lines := strings.Split(strings.TrimRight(actual, "\n"), "\n")
				require.Len(t, lines, 3, "chain with extras (full chain walk) must produce 3 lines")
				assert.Contains(t, actual, "Test Root CA")
				assert.Contains(t, actual, "Test Intermediate CA")
				assert.Contains(t, actual, "[spiffe://example.com/workload]")
				assert.NotContains(t, actual, "Stale Intermediate", "stale intermediates must not appear in chain output")
			},
		},
		{
			name:         "chain-with-extras.pem/shortest.chain",
			pemPath:      "testdata/chain-with-extras.pem",
			format:       "chain",
			goldenSuffix: ".shortest.chain",
			bundle:       "testdata/chain-with-extras.roots.pem",
			shortestPath: true,
			extraChecks: func(t *testing.T, actual string) {
				lines := strings.Split(strings.TrimRight(actual, "\n"), "\n")
				require.Len(t, lines, 3, "shortest path must have exactly 3 certs: root, live intermediate, leaf")
				assert.Contains(t, actual, "Test Root CA")
				assert.Contains(t, actual, "Test Intermediate CA")
				assert.Contains(t, actual, "[spiffe://example.com/workload]")
				assert.NotContains(t, actual, "Stale Intermediate", "stale intermediates must be excluded from shortest path")
			},
		},
	}

	for _, tt := range rows {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			goldenSuffix := tt.goldenSuffix
			if goldenSuffix == "" {
				goldenSuffix = "." + tt.format
			}
			goldenPath := tt.pemPath + goldenSuffix

			var actual string
			if tt.useSummary {
				certs, err := pemutil.LoadCertificates(tt.pemPath)
				require.NoError(t, err)
				var convErr error
				actual, convErr = convertCertsToSummary(certs, X509ConvertOptions{Output: X509InspectOutputOptions{TimeZone: "UTC"}}, goldenTime)
				require.NoError(t, convErr)
			} else {
				i := &X509Inspector{
					Filename:      tt.pemPath,
					OutputFormat:  tt.format,
					Bundle:        tt.bundle,
					ShortestPath:  tt.shortestPath,
					TreeFields:    tt.treeFields,
					OutputOptions: tt.outputOpts,
				}
				var err error
				actual, err = i.Inspect()
				require.NoError(t, err)
			}

			golden := readOrUpdateGolden(t, goldenPath, actual)

			switch tt.comparison {
			case "json":
				require.JSONEq(t, golden, actual)
			case "yaml":
				require.YAMLEq(t, golden, actual)
			default:
				assert.Equal(t, golden, actual)
			}

			if tt.extraChecks != nil {
				tt.extraChecks(t, actual)
			}
		})
	}
}

// TestInspect_ChainShortestPath_VerbatimError drives X509Inspector.Inspect() end-to-end
// with --format chain --shortest-path against a PEM that contains a leaf and an unrelated
// self-signed root. The leaf cannot chain to the unrelated root, so Verify fails.
// After the inspector-layer fix the error must reach the caller unwrapped: no
// "error converting certificates to Chain:" prefix, and errors.As must resolve to
// x509.UnknownAuthorityError.
func TestInspect_ChainShortestPath_VerbatimError(t *testing.T) {
	_, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	unrelatedCA := testx509.NewCertificateAuthority(t, "Unrelated Root")
	unrelatedRoot := unrelatedCA.GenerateCaCertificate(t)

	path := writeCerts(t, leaf, unrelatedRoot)

	i := X509Inspector{
		Filename:     path,
		OutputFormat: "chain",
		ShortestPath: true,
	}
	_, err := i.Inspect()
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "error converting", "error must not carry inspector-layer prefix")
	assert.NotContains(t, err.Error(), "verify chain for leaf", "error must not carry chain-layer prefix")

	var unknownAuth x509.UnknownAuthorityError
	assert.True(t, errors.As(err, &unknownAuth), "underlying error must be x509.UnknownAuthorityError")
}

// TestInspect_NonChainConverterError_WrapsError is a regression guard verifying that errors
// from non-chain/tree converters (json, yaml, summary) continue to be wrapped with
// "error converting certificates to <Label>:" so diagnostic messages remain attributable.
// If isChainOrTree were accidentally broadened to all text-lexer formats this test would catch it.
func TestInspect_NonChainConverterError_WrapsError(t *testing.T) {
	const testFormat = "test-format-that-always-fails"
	wantErr := fmt.Errorf("synthetic converter failure")

	FormatMap[testFormat] = inspect.Formatter[[]*x509.Certificate, X509ConvertOptions]{
		Label: "TestFmt",
		Lexer: "json",
		Converter: func(_ []*x509.Certificate, _ X509ConvertOptions) (string, error) {
			return "", wantErr
		},
	}
	t.Cleanup(func() { delete(FormatMap, testFormat) })

	_, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	path := writeCerts(t, leaf)

	i := X509Inspector{Filename: path, OutputFormat: testFormat}
	_, err := i.Inspect()
	require.Error(t, err)

	assert.Contains(t, err.Error(), "error converting certificates to TestFmt:",
		"non-chain/tree converter errors must still carry the inspector-layer prefix")
	assert.ErrorIs(t, err, wantErr, "wrapped error must unwrap to the original converter error")
}

// TestInspect_ChainShortestPath_VerbatimError_ExpiredLeaf is a regression guard
// complementing TestInspect_ChainShortestPath_VerbatimError. It drives Inspect()
// end-to-end with --format chain --shortest-path against an expired SPIFFE leaf cert
// rooted at a valid self-signed CA. leaf.Verify() returns x509.CertificateInvalidError
// (not x509.UnknownAuthorityError), exercising the non-UnknownAuthority error path.
// The error must reach the caller without any inspector-layer or chain-layer prefix.
func TestInspect_ChainShortestPath_VerbatimError_ExpiredLeaf(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test Root CA", testx509.WithSigner(caKey))
	root := ca.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/expired-workload")
	require.NoError(t, err)
	issuer := ca.GetIssuerTemplate(t)
	leafTmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "expired-workload"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour), // already expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
		AuthorityKeyId:        issuer.SubjectKeyId,
	}
	expiredLeaf := testx509.CreateCertificate(t, &leafTmpl, &issuer, leafKey.Public(), caKey)

	path := writeCerts(t, expiredLeaf, root)

	i := X509Inspector{
		Filename:     path,
		OutputFormat: "chain",
		ShortestPath: true,
	}
	_, err = i.Inspect()
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "error converting", "error must not carry inspector-layer prefix")
	assert.NotContains(t, err.Error(), "verify chain for leaf", "error must not carry chain-layer prefix")

	var certInvalidErr x509.CertificateInvalidError
	assert.True(t, errors.As(err, &certInvalidErr), "underlying error must be x509.CertificateInvalidError; got: %T: %v", err, err)
}

// TestInspector_ConverterStderr_PropagatedFromInspector verifies that
// X509Inspector.Inspect() routes its resolved stderr writer into the converter
// options (convertOpts.Stderr = stderr at inspector.go:115), so converter-emitted
// diagnostics reach the caller-supplied writer. Uses a cross-signed topology to
// exercise the chain alternate-path branch; skips if x509.Verify returns only one
// chain on this Go build (the diagnostic branch is then unreachable).
func TestInspector_ConverterStderr_PropagatedFromInspector(t *testing.T) {
	rootCA_A := testx509.NewCertificateAuthority(t, "Propagation Root A")
	rootA := rootCA_A.GenerateCaCertificate(t)
	rootCA_B := testx509.NewCertificateAuthority(t, "Propagation Root B")
	rootB := rootCA_B.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intSignedByA := rootCA_A.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Propagation X-Signed Int"}),
	)
	intSignedByB := rootCA_B.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Propagation X-Signed Int"}),
	)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/propagation-test")
	require.NoError(t, err)
	leaf := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(301),
		Subject:               pkix.Name{CommonName: "propagation-test-workload"},
		NotBefore:             rootA.NotBefore,
		NotAfter:              rootA.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, intSignedByA, leafKey.Public(), intKey)

	chainPath := writeCerts(t, intSignedByA, intSignedByB, leaf)
	bundlePath := writeCerts(t, rootA, rootB)

	var stderrBuf strings.Builder
	i := X509Inspector{
		Filename:     chainPath,
		Bundle:       bundlePath,
		OutputFormat: "chain",
		ShortestPath: true,
		Stderr:       &stderrBuf,
	}
	_, err = i.Inspect()
	require.NoError(t, err)

	note := stderrBuf.String()
	if !strings.Contains(note, "of equal length") {
		t.Skip("x509.Verify returned only one chain; alternate-path branch not reachable on this Go build")
	}
	assert.Contains(t, note, "alternate path",
		"converter alternate-path note must be routed through X509Inspector.Stderr")
}

// goldenNamingViolations scans dir non-recursively and returns the names of all files that do not
// follow the <pemPath>.<format> convention. A file is valid when it ends with ".pem" (input
// fixture) or has the form <base>.pem<suffix> where <suffix> is in allowedSuffixes.
func goldenNamingViolations(dir string, allowedSuffixes []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".pem") {
			continue
		}
		valid := false
		for _, suf := range allowedSuffixes {
			if strings.HasSuffix(e.Name(), ".pem"+suf) {
				valid = true
				break
			}
		}
		if !valid {
			violations = append(violations, e.Name())
		}
	}
	return violations, nil
}

// TestGoldenFiles_NamingConventionEnforced is a regression guard that asserts every file in
// internal/x509inspect/testdata/ follows the <pemPath>.<format> naming convention. It prevents
// reintroduction of the short-named scheme (e.g. chain-3-deep.chain) eliminated by the
// four-commit consolidation series (fad68f39, 9efabca0, d9c52b5c, ab3cddbd).
func TestGoldenFiles_NamingConventionEnforced(t *testing.T) {
	// allowedSuffixes is the canonical set of golden-file suffixes. Add one entry here when a new format is added.
	allowedSuffixes := []string{".json", ".yaml", ".summary", ".chain", ".tree", ".tree.full", ".shortest.chain"}

	violations, err := goldenNamingViolations("testdata", allowedSuffixes)
	require.NoError(t, err)
	for _, name := range violations {
		t.Errorf("testdata/%s: does not follow the <pemPath>.<format> naming convention; "+
			"allowed golden suffixes (after .pem): %v", name, allowedSuffixes)
	}
}

// TestGoldenFiles_NamingConventionEnforced_DetectsViolations verifies that goldenNamingViolations
// correctly identifies short-named files that lack the required .pem infix.
func TestGoldenFiles_NamingConventionEnforced_DetectsViolations(t *testing.T) {
	allowedSuffixes := []string{".json", ".yaml", ".summary", ".chain", ".tree", ".tree.full", ".shortest.chain"}

	tests := []struct {
		name           string
		filenames      []string
		wantViolations []string
	}{
		{
			name:           "short chain name missing pem infix",
			filenames:      []string{"chain-3-deep.chain"},
			wantViolations: []string{"chain-3-deep.chain"},
		},
		{
			name:           "short tree name missing pem infix",
			filenames:      []string{"chain-3-deep.tree"},
			wantViolations: []string{"chain-3-deep.tree"},
		},
		{
			name:           "unknown extension",
			filenames:      []string{"foo.bar"},
			wantViolations: []string{"foo.bar"},
		},
		{
			name:           "valid pem input fixture accepted",
			filenames:      []string{"chain-3-deep.pem"},
			wantViolations: nil,
		},
		{
			name:           "valid pem.chain golden accepted",
			filenames:      []string{"chain-3-deep.pem.chain"},
			wantViolations: nil,
		},
		{
			name:           "mix: valid pem, valid golden, and short-named violation",
			filenames:      []string{"chain-3-deep.pem", "chain-3-deep.pem.chain", "chain-3-deep.chain"},
			wantViolations: []string{"chain-3-deep.chain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			for _, fname := range tt.filenames {
				require.NoError(t, os.WriteFile(filepath.Join(tmpDir, fname), []byte(""), 0600))
			}
			violations, err := goldenNamingViolations(tmpDir, allowedSuffixes)
			require.NoError(t, err)
			require.Equal(t, tt.wantViolations, violations)
		})
	}
}
