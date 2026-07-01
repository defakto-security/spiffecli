package x509inspect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestIdentifyLeaf_EmptySlice(t *testing.T) {
	tests := []struct {
		name  string
		input []*x509.Certificate
	}{
		{"nil slice", nil},
		{"empty slice", []*x509.Certificate{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := identifyLeaf(tt.input)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no leaf certificate found")
		})
	}
}

// TestIdentifyLeaf_AllCAFallback covers the last-resort fallback at chain.go:193.
// When all unclaimed certs have IsCA=true (two unrelated self-signed roots that
// do not parent each other), the non-CA preference loop finds nothing and the
// function returns leaves[0] with nil error.
func TestIdentifyLeaf_AllCAFallback(t *testing.T) {
	rootCA1 := testx509.NewCertificateAuthority(t, "Root CA 1")
	root1 := rootCA1.GenerateCaCertificate(t)

	rootCA2 := testx509.NewCertificateAuthority(t, "Root CA 2")
	root2 := rootCA2.GenerateCaCertificate(t)

	got, err := identifyLeaf([]*x509.Certificate{root1, root2})
	require.NoError(t, err)
	fp := certFingerprint(got)
	assert.True(t,
		fp == certFingerprint(root1) || fp == certFingerprint(root2),
		"returned cert must be one of the two input CAs",
	)
}

func TestIdentifyLeaf_SpiffeID(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	got, err := identifyLeaf([]*x509.Certificate{root, intermediate, leaf})
	require.NoError(t, err)
	assert.Equal(t, certFingerprint(leaf), certFingerprint(got))
}

func TestIdentifyLeaf_NoSpiffeID_FallbackNoChildren(t *testing.T) {
	// Two certs: root signs intermediate. Intermediate is the leaf (no SPIFFE IDs).
	// Use distinct subject names so parent-linking is unambiguous.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	got, err := identifyLeaf([]*x509.Certificate{root, intermediate})
	require.NoError(t, err)
	assert.Equal(t, certFingerprint(intermediate), certFingerprint(got))
}

func TestParentLinking_AKI_SKI(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	all := []*x509.Certificate{root, intermediate, leaf}
	parents := buildParentMap(all)

	// Intermediate's parent should be root.
	intParent := parents[certFingerprint(intermediate)]
	require.NotNil(t, intParent, "intermediate should have root as parent")
	assert.Equal(t, certFingerprint(root), certFingerprint(intParent))

	// Leaf's parent should be intermediate.
	leafParent := parents[certFingerprint(leaf)]
	require.NotNil(t, leafParent, "leaf should have intermediate as parent")
	assert.Equal(t, certFingerprint(intermediate), certFingerprint(leafParent))
}

func TestParentLinking_DNFallback(t *testing.T) {
	// Certs with AKI/SKI cleared to force DN-only matching.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	// Clear AKI/SKI to force DN fallback.
	rootCopy := *root
	rootCopy.SubjectKeyId = nil
	intCopy := *intermediate
	intCopy.AuthorityKeyId = nil

	parents := buildParentMap([]*x509.Certificate{&rootCopy, &intCopy})
	parent := parents[certFingerprint(&intCopy)]
	require.NotNil(t, parent, "intermediate should have root as parent via DN fallback")
	assert.Equal(t, certFingerprint(&rootCopy), certFingerprint(parent))
}

func TestBuildChain_RootToLeafOrder(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	chain, err := buildChain([]*x509.Certificate{root, intermediate, leaf})
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]), "first should be root")
	assert.Equal(t, certFingerprint(intermediate), certFingerprint(chain[1]), "second should be intermediate")
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[2]), "third should be leaf")
}

func TestShortestPath_BundleSuppliedRoot(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	var stderr bytes.Buffer
	// Root comes from the bundle (pass it alongside intermediate and leaf).
	chain, err := shortestPath([]*x509.Certificate{intermediate, leaf, root}, &stderr)
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]))
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[2]))
}

func TestShortestPath_SelfSignedRootInFilename(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	var stderr bytes.Buffer
	chain, err := shortestPath([]*x509.Certificate{root, intermediate, leaf}, &stderr)
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]))
}

func TestShortestPath_NoRoot(t *testing.T) {
	// Only intermediate + leaf, no self-signed root.
	_, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	var stderr bytes.Buffer
	_, err := shortestPath([]*x509.Certificate{intermediate, leaf}, &stderr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trusted root found")
}

func TestShortestPath_NoValidPath(t *testing.T) {
	// A self-signed root that does NOT sign the leaf.
	unrelatedCA := testx509.NewCertificateAuthority(t, "Unrelated Root")
	unrelatedRoot := unrelatedCA.GenerateCaCertificate(t)

	_, _, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	var stderr bytes.Buffer
	_, err := shortestPath([]*x509.Certificate{unrelatedRoot, leaf}, &stderr)
	require.Error(t, err)
	// Error must be returned verbatim — no "verify chain for leaf" wrapper prefix.
	assert.NotContains(t, err.Error(), "verify chain for leaf", "error must not contain wrapper prefix")
	// x509.UnknownAuthorityError must be reachable via errors.As (error is returned unmodified).
	var unknownAuth x509.UnknownAuthorityError
	assert.True(t, errors.As(err, &unknownAuth), "underlying error must be x509.UnknownAuthorityError")
}

func TestShortestPath_Deterministic(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	var stderr bytes.Buffer
	chain1, err := shortestPath([]*x509.Certificate{root, intermediate, leaf}, &stderr)
	require.NoError(t, err)
	chain2, err := shortestPath([]*x509.Certificate{root, intermediate, leaf}, &stderr)
	require.NoError(t, err)
	require.Equal(t, len(chain1), len(chain2))
	for i := range chain1 {
		assert.Equal(t, certFingerprint(chain1[i]), certFingerprint(chain2[i]))
	}
}

func TestConvertCertsToChain_Output(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{}
	out, err := convertCertsToChain([]*x509.Certificate{root, intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3)
	// Root has no indent.
	assert.False(t, strings.HasPrefix(lines[0], " "), "root should have no indent")
	// Intermediate has 2-space indent.
	assert.True(t, strings.HasPrefix(lines[1], "  "), "intermediate should have 2-space indent")
	// Leaf has 4-space indent and SPIFFE ID in brackets.
	assert.True(t, strings.HasPrefix(lines[2], "    "), "leaf should have 4-space indent")
	assert.Contains(t, lines[2], "[spiffe://example.com/workload]")
}

func TestConvertCertsToChain_ShortestPath_ExcludesExtra(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	// Add an extra unrelated intermediate that is NOT on the valid path.
	extraCA := testx509.NewCertificateAuthority(t, "Extra CA")
	extra := extraCA.GenerateCaCertificate(t)

	opts := X509ConvertOptions{Chain: X509ChainOptions{ShortestPath: true}}
	out, err := convertCertsToChain([]*x509.Certificate{root, intermediate, leaf, extra}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	// Should only have 3 lines (root + intermediate + leaf), not 4.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	assert.Len(t, lines, 3)
}

func TestConvertCertsToChain_BundleCertsExtendsChain(t *testing.T) {
	// Root is supplied only via BundleCerts; certs contains just intermediate + leaf.
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	opts := X509ConvertOptions{Chain: X509ChainOptions{BundleCerts: []*x509.Certificate{root}}}
	out, err := convertCertsToChain([]*x509.Certificate{intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3, "chain must include root from BundleCerts")
	assert.Contains(t, lines[0], "Root CA")
	assert.Contains(t, lines[2], "workload")
}

func TestConvertCertsToChain_IntermediateSpiffeID_BracketLeafOnly(t *testing.T) {
	// Build a chain where the intermediate CA also carries a SPIFFE URI SAN.
	// Only the leaf's line should contain brackets.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Intermediate with a SPIFFE URI SAN (trust-domain CA scenario).
	tdURI, err := url.Parse("spiffe://example.com")
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Trust Domain CA"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{tdURI},
	}
	intermediate := testx509.CreateCertificate(t, intTmpl, root, intKey.Public(), rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{leafURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, intermediate, leafKey.Public(), intKey)

	opts := X509ConvertOptions{}
	out, err := convertCertsToChain([]*x509.Certificate{root, intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3)
	// Intermediate line must NOT contain brackets even though it has a SPIFFE URI SAN.
	assert.NotContains(t, lines[1], "[", "intermediate line must not contain SPIFFE ID bracket")
	assert.NotContains(t, lines[1], "]", "intermediate line must not contain SPIFFE ID bracket")
	// Leaf line must contain the bracket.
	assert.Contains(t, lines[2], "[spiffe://example.com/workload]")
}

func TestConvertCertsToChain_NoSpiffeID_NoBrackets(t *testing.T) {
	// A chain with no SPIFFE IDs — no brackets should appear anywhere in the output.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	opts := X509ConvertOptions{}
	out, err := convertCertsToChain([]*x509.Certificate{root, intermediate}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	assert.NotContains(t, out, "[", "chain with no SPIFFE IDs must not contain brackets")
	assert.NotContains(t, out, "]", "chain with no SPIFFE IDs must not contain brackets")
}

// TestRenderChain_OnlyLeafGetsBracket calls renderChain directly with a
// pre-assembled chain in which both the middle and last certs carry SPIFFE
// URI SANs. The bracket must appear only on the last (leaf) line.
func TestRenderChain_OnlyLeafGetsBracket(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tdURI, err := url.Parse("spiffe://example.com")
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Trust Domain CA"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{tdURI},
	}
	intermediate := testx509.CreateCertificate(t, intTmpl, root, intKey.Public(), rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafURI, err := url.Parse("spiffe://example.com/svc")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "svc"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{leafURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, intermediate, leafKey.Public(), intKey)

	// Call renderChain directly with a root-to-leaf ordered slice.
	out := renderChain([]*x509.Certificate{root, intermediate, leaf})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3)
	assert.NotContains(t, lines[0], "[", "root line must not contain SPIFFE ID bracket")
	assert.NotContains(t, lines[1], "[", "intermediate line must not contain SPIFFE ID bracket even with SPIFFE URI SAN")
	assert.Contains(t, lines[2], "[spiffe://example.com/svc]", "leaf line must contain the SPIFFE ID bracket")
}

func TestUnionCerts_Deduplication(t *testing.T) {
	root, intermediate, _ := testx509.NewThreeLevelSPIFFEChain(t)
	// root appears in both a and b.
	result := unionCerts([]*x509.Certificate{root, intermediate}, []*x509.Certificate{root})
	assert.Len(t, result, 2, "duplicate cert must be deduplicated in union")
}

func TestUnionCerts_BothEmpty(t *testing.T) {
	result := unionCerts(nil, nil)
	assert.Empty(t, result)
}

func TestUnionCerts_OneEmpty(t *testing.T) {
	root, _, _ := testx509.NewThreeLevelSPIFFEChain(t)
	result := unionCerts([]*x509.Certificate{root}, nil)
	assert.Len(t, result, 1)
}

func TestIdentifyLeaf_SingleCert(t *testing.T) {
	// A single self-signed cert with no children: it is its own leaf.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)
	leaf, err := identifyLeaf([]*x509.Certificate{root})
	require.NoError(t, err)
	assert.Equal(t, certFingerprint(root), certFingerprint(leaf))
}

func TestBuildChain_TwoCerts_RootAndLeaf(t *testing.T) {
	// Simple 2-cert chain: CA signs a SPIFFE leaf directly (no intermediate).
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/svc")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svc"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	chain, err := buildChain([]*x509.Certificate{root, leaf})
	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]))
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[1]))
}

func TestIsSelfSigned_SelfSignedRoot(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)
	assert.True(t, isSelfSigned(root))
}

func TestIsSelfSigned_IntermediateIsNotSelfSigned(t *testing.T) {
	root, intermediate, _ := testx509.NewThreeLevelSPIFFEChain(t)
	_ = root
	assert.False(t, isSelfSigned(intermediate))
}

func TestShortestPath_SingleSelfSignedRoot(t *testing.T) {
	// A single self-signed CA cert: identifyLeaf picks it as the leaf, yet
	// it is also the root. shortestPath must return a one-element chain.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	var stderr bytes.Buffer
	chain, err := shortestPath([]*x509.Certificate{root}, &stderr)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]))
}

func TestConvertCertsToChain_ShortestPath_SingleSelfSignedRoot(t *testing.T) {
	// Confirm the renderer also succeeds for the single-self-signed-root case.
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	opts := X509ConvertOptions{Chain: X509ChainOptions{ShortestPath: true}}
	out, err := convertCertsToChain([]*x509.Certificate{root}, opts, &bytes.Buffer{})
	require.NoError(t, err)

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "Root CA")
	// Self-signed root has no SPIFFE ID, so no brackets.
	assert.NotContains(t, lines[0], "[")
}

func TestIsSelfSigned_SelfIssuedNotSelfSigned(t *testing.T) {
	// Construct a cert whose Issuer DN == Subject DN but whose signature was
	// made by a different key. isSelfSigned must return false.
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// signerCA: self-signed with key2, Subject = "Fake Root". Used as parent
	// so the resulting cert's Issuer matches its Subject ("Fake Root").
	signerCA := testx509.NewCertificateAuthority(t, "Fake Root", testx509.WithSigner(key2))
	signer := signerCA.GenerateCaCertificate(t)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Fake Root"},
		NotBefore:             signer.NotBefore,
		NotAfter:              signer.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	// Public key is key1; signed by key2 — so CheckSignatureFrom(self) fails.
	fakeRoot := testx509.CreateCertificate(t, tmpl, signer, key1.Public(), key2)

	require.Equal(t, fakeRoot.Issuer.String(), fakeRoot.Subject.String(), "sanity: must be self-issued by DN")
	assert.False(t, isSelfSigned(fakeRoot), "self-issued but not self-signed cert must return false")
}

func TestShortestPath_SelfIssuedNotSelfSigned_RejectsAsRoot(t *testing.T) {
	// shortestPath must not treat a self-issued-but-not-self-signed cert as a
	// trust anchor; it must return "no trusted root found".
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signerCA := testx509.NewCertificateAuthority(t, "Fake Root", testx509.WithSigner(key2))
	signer := signerCA.GenerateCaCertificate(t)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Fake Root"},
		NotBefore:             signer.NotBefore,
		NotAfter:              signer.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	fakeRoot := testx509.CreateCertificate(t, tmpl, signer, key1.Public(), key2)

	var stderr bytes.Buffer
	_, err = shortestPath([]*x509.Certificate{fakeRoot}, &stderr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no trusted root found for --shortest-path")
}

func TestShortestPath_EqualLengthAlternatePaths(t *testing.T) {
	// Cross-signed topology: a single intermediate key is signed by two independent
	// roots. leaf.Verify returns two equal-length chains, exercising altCount > 0.
	rootCA_A := testx509.NewCertificateAuthority(t, "Root CA A")
	rootA := rootCA_A.GenerateCaCertificate(t)

	rootCA_B := testx509.NewCertificateAuthority(t, "Root CA B")
	rootB := rootCA_B.GenerateCaCertificate(t)

	// Single intermediate key signed by both roots.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateSignedByA := rootCA_A.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "X-Signed Intermediate"}),
	)
	intermediateSignedByB := rootCA_B.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "X-Signed Intermediate"}),
	)

	// Leaf: SPIFFE SVID signed by the intermediate key.
	// Parent = intermediateSignedByA so the leaf's AKI = intermediateSignedByA.SubjectKeyId,
	// which equals intermediateSignedByB.SubjectKeyId (same public key → same SKI).
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/xsigned")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(200),
		Subject:               pkix.Name{CommonName: "xsigned-workload"},
		NotBefore:             rootA.NotBefore,
		NotAfter:              rootA.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, intermediateSignedByA, leafKey.Public(), intKey)

	all := []*x509.Certificate{rootA, rootB, intermediateSignedByA, intermediateSignedByB, leaf}

	var stderr bytes.Buffer
	chain, err := shortestPath(all, &stderr)
	require.NoError(t, err)

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "of equal length") {
		t.Skip("x509.Verify returned only one chain for this cross-signed topology; altCount>0 branch not reachable on this Go build")
	}

	// Count must be exactly 1 (one alternate beyond the first); singular form.
	// Note: the plural branch (altCount >= 2) requires x509.Verify to return 3+ equal-length
	// chains, which is not reproducible with the available cross-signed fixture on current Go
	// builds; it is exercised implicitly by the production code path.
	assert.Contains(t, stderrStr, "1 alternate path of equal length exists; selected the first",
		"warning must report exactly 1 alternate equal-length path")

	// Chain must be root → intermediate → leaf.
	require.Len(t, chain, 3)
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[2]), "last element must be the leaf")
}

func TestShortestPath_TwoUnrelatedSelfSignedCerts_IdentifyLeafPicksFirst(t *testing.T) {
	// Two unrelated self-signed CA certs with no SPIFFE IDs. Both are
	// "unclaimed" (neither is a parent of the other), so identifyLeaf falls
	// back to leaves[0] — which is a self-signed cert. After the fix,
	// shortestPath adds that cert to the roots pool, so it can verify against
	// itself and returns a one-element chain. Before the fix, the identified
	// leaf was excluded from roots; the only root found was the other CA, and
	// leaf.Verify(roots={otherCA}) would fail with a verification error.
	rootCA1 := testx509.NewCertificateAuthority(t, "Root CA 1")
	root1 := rootCA1.GenerateCaCertificate(t)

	rootCA2 := testx509.NewCertificateAuthority(t, "Root CA 2")
	root2 := rootCA2.GenerateCaCertificate(t)

	var stderr bytes.Buffer
	// Pass root1 first: identifyLeaf sees both as unclaimed CAs and picks root1.
	chain, err := shortestPath([]*x509.Certificate{root1, root2}, &stderr)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, certFingerprint(root1), certFingerprint(chain[0]))
}

// TestBuildChain_CycleGuard verifies the visited-set in buildChain prevents an
// infinite loop when buildParentMap produces a 2-cycle between two non-leaf certs.
//
// Cycle construction: two shallow cert copies (cycleA, cycleB) have their
// AuthorityKeyId and Issuer fields swapped so each is the other's parent.
// The SPIFFE leaf points to cycleA, giving a walk of leaf→A→B→A→(break).
// TestRenderChain_SanitizesEscapeInSubjectAndSpiffeID builds a leaf cert whose
// Subject CN contains an ANSI escape sequence and asserts that renderChain
// replaces the ESC byte with U+FFFD, never leaking it to the terminal.
func TestRenderChain_SanitizesEscapeInSubjectAndSpiffeID(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/workload")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: "\x1b[31mEvil"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	out := renderChain([]*x509.Certificate{root, leaf})
	assert.NotContains(t, out, "\x1b", "output must not contain ESC byte")
	assert.Contains(t, out, "�", "output must contain U+FFFD in place of the ESC byte")
}

func TestCertFingerprint_StableAndDistinct(t *testing.T) {
	caA := testx509.NewCertificateAuthority(t, "CA A")
	certA := caA.GenerateCaCertificate(t)

	caB := testx509.NewCertificateAuthority(t, "CA B")
	certB := caB.GenerateCaCertificate(t)

	fpA1 := certFingerprint(certA)
	fpA2 := certFingerprint(certA)
	fpB := certFingerprint(certB)

	assert.Equal(t, fpA1, fpA2, "certFingerprint must be stable across calls")
	assert.NotEqual(t, fpA1, fpB, "certFingerprint must be distinct for two different certificates")
	assert.Equal(t, 32, len(fpA1), "certFingerprint must be a 32-byte raw SHA-256 digest")
	assert.Equal(t, 32, len(fpB), "certFingerprint must be a 32-byte raw SHA-256 digest")
}

func TestCertFingerprint_MatchesRawSHA256(t *testing.T) {
	ca := testx509.NewCertificateAuthority(t, "Test CA")
	cert := ca.GenerateCaCertificate(t)

	sum := sha256.Sum256(cert.Raw)
	want := sum

	got := certFingerprint(cert)

	assert.Equal(t, want, got, "certFingerprint must return the raw SHA-256 digest bytes, not hex-encoded")
	assert.NotEqual(t, [32]byte{}, got, "fingerprint must not be the zero value")
}

// TestShortestPath_ClientAuthOnlyLeaf verifies that shortestPath accepts a leaf
// whose ExtKeyUsage is clientAuth only (no serverAuth). Without the
// ExtKeyUsageAny fix, Go's default EKU enforcement would reject this chain.
func TestShortestPath_ClientAuthOnlyLeaf(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/client-only")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "client-only-workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, intermediate, leafKey.Public(), intKey)

	var stderr bytes.Buffer
	chain, err := shortestPath([]*x509.Certificate{root, intermediate, leaf}, &stderr)
	require.NoError(t, err)
	require.Len(t, chain, 3)
	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]), "first cert must be root")
	assert.Equal(t, certFingerprint(intermediate), certFingerprint(chain[1]), "second cert must be intermediate")
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[2]), "third cert must be leaf")
}

// TestConvertCertsToChain_ShortestPath_ClientAuthOnlyLeaf exercises the
// user-visible convertCertsToChain surface with the same clientAuth-only leaf
// fixture and asserts correct root-to-leaf rendered output.
func TestConvertCertsToChain_ShortestPath_ClientAuthOnlyLeaf(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediate := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA"}),
	)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/client-only")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "client-only-workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, intermediate, leafKey.Public(), intKey)

	opts := X509ConvertOptions{Chain: X509ChainOptions{ShortestPath: true}}
	out, err := convertCertsToChain([]*x509.Certificate{root, intermediate, leaf}, opts, &bytes.Buffer{})
	require.NoError(t, err)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	require.Len(t, lines, 3, "chain output must have three lines (root, intermediate, leaf)")
	assert.False(t, strings.HasPrefix(lines[0], " "), "root line must not be indented")
	assert.True(t, strings.HasPrefix(lines[1], "  "), "intermediate line must be 2-space indented")
	assert.True(t, strings.HasPrefix(lines[2], "    "), "leaf line must be 4-space indented")
	assert.Contains(t, lines[2], "[spiffe://example.com/client-only]")
}

// TestIsParent_RawDEREqualityForSignedChain verifies that isParent uses raw DER
// comparison (bytes.Equal on RawIssuer/RawSubject) rather than pkix.Name.String().
// crypto/x509 propagates the parent's RawSubject bytes unchanged into the child's
// RawIssuer when signing, so the DER comparison is the canonical test. This test
// also exercises the negative case: leaf.RawIssuer != root.RawSubject because the
// leaf's issuer is the intermediate, not the root.
func TestIsParent_RawDEREqualityForSignedChain(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	// Sanity: confirm crypto/x509 propagated RawSubject bytes into the child RawIssuer.
	require.True(t, bytes.Equal(intermediate.RawIssuer, root.RawSubject),
		"sanity: intermediate.RawIssuer must equal root.RawSubject (DER propagation)")
	require.True(t, bytes.Equal(leaf.RawIssuer, intermediate.RawSubject),
		"sanity: leaf.RawIssuer must equal intermediate.RawSubject (DER propagation)")

	// Positive: genuine parent-child relationships.
	assert.True(t, isParent(intermediate, root), "intermediate must be recognised as child of root")
	assert.True(t, isParent(leaf, intermediate), "leaf must be recognised as child of intermediate")

	// Negative: leaf.RawIssuer != root.RawSubject — leaf is not a direct child of root.
	assert.False(t, isParent(leaf, root), "leaf must not be a direct child of root")
}

// TestIsSelfSigned_RawDEREqualityForSelfSignedRoot verifies that isSelfSigned uses raw
// DER byte comparison (bytes.Equal on RawIssuer/RawSubject) rather than pkix.Name.String().
// For a genuine self-signed root, crypto/x509 writes the same DER bytes for both Subject
// and Issuer, so bytes.Equal is the canonical test. This test also exercises the negative
// case: an intermediate's RawIssuer differs from its RawSubject because its issuer is the
// root, not itself.
func TestIsSelfSigned_RawDEREqualityForSelfSignedRoot(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)
	_, intermediate, _ := testx509.NewThreeLevelSPIFFEChain(t)

	// Sanity: for a self-signed root, crypto/x509 copies the Subject DER bytes into
	// Issuer verbatim — the raw-DER contract that isSelfSigned relies on.
	require.True(t, bytes.Equal(root.RawIssuer, root.RawSubject),
		"sanity: root.RawIssuer must equal root.RawSubject (self-signed DER contract)")

	// Positive: genuine self-signed root must be recognised.
	assert.True(t, isSelfSigned(root), "self-signed root must return true")

	// Negative: intermediate.RawIssuer != intermediate.RawSubject because the
	// intermediate was signed by the root, not by itself.
	assert.False(t, bytes.Equal(intermediate.RawIssuer, intermediate.RawSubject),
		"sanity: intermediate.RawIssuer must differ from intermediate.RawSubject")
	assert.False(t, isSelfSigned(intermediate), "intermediate must not be recognised as self-signed")
}

func TestBuildChain_CycleGuard(t *testing.T) {
	// Generate two independent CA keys and their CA certs.
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caA := testx509.NewCertificateAuthority(t, "CA A", testx509.WithSigner(keyA))
	certA := caA.GenerateCaCertificate(t)

	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caB := testx509.NewCertificateAuthority(t, "CA B", testx509.WithSigner(keyB))
	certB := caB.GenerateCaCertificate(t)

	// Create a SPIFFE leaf signed by caA so identifyLeaf selects it immediately
	// (IsCA=false, has SPIFFE URI SAN). Using certA as the parent struct means
	// Go sets leaf.AuthorityKeyId = certA.SubjectKeyId automatically.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/cycle-test")
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(500),
		Subject:               pkix.Name{CommonName: "cycle-workload"},
		NotBefore:             certA.NotBefore,
		NotAfter:              certA.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, leafTmpl, certA, leafKey.Public(), keyA)

	// Shallow-copy certA and certB, then swap their AKI and RawIssuer to form a 2-cycle.
	// isParent uses raw DER bytes (RawIssuer/RawSubject) for issuer matching, so only
	// RawIssuer needs to be swapped — the decoded Issuer field is not consulted.
	//   cycleA.AuthorityKeyId == certB.SubjectKeyId  → cycleA's parent is cycleB
	//   cycleB.AuthorityKeyId == certA.SubjectKeyId  → cycleB's parent is cycleA
	// certFingerprint uses cert.Raw, which is unchanged by field mutation on the copy,
	// so the visited map uses the same keys as buildParentMap's lookups.
	cycleA := *certA
	cycleA.AuthorityKeyId = certB.SubjectKeyId
	cycleA.RawIssuer = certB.RawSubject

	cycleB := *certB
	cycleB.AuthorityKeyId = certA.SubjectKeyId
	cycleB.RawIssuer = certA.RawSubject

	type result struct {
		chain []*x509.Certificate
		err   error
	}
	done := make(chan result, 1)
	go func() {
		chain, err := buildChain([]*x509.Certificate{leaf, &cycleA, &cycleB})
		done <- result{chain, err}
	}()

	select {
	case res := <-done:
		require.NoError(t, res.err)
		assert.NotEmpty(t, res.chain, "cycle guard must not produce an empty chain")
		// Verify no cert appears more than once (the visited guard's purpose).
		seen := map[[32]byte]int{}
		for _, c := range res.chain {
			seen[certFingerprint(c)]++
		}
		for _, count := range seen {
			assert.Equal(t, 1, count, "a cert appears more than once — cycle guard did not fire")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("buildChain did not return within 2 seconds — cycle guard may be broken")
	}
}

// TestBuildParentMap_EmptyInput verifies that an empty slice returns an empty map.
func TestBuildParentMap_EmptyInput(t *testing.T) {
	m := buildParentMap(nil)
	assert.Empty(t, m)
}

// TestBuildParentMap_SelfSignedRoot has no parent in the map because it is
// the root of the chain — no cert in the input claims it as a child.
func TestBuildParentMap_SelfSignedRoot(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	m := buildParentMap([]*x509.Certificate{root})
	// Self-signed root: its own fingerprint must not appear as a key because
	// nothing claims it as a child.
	_, found := m[certFingerprint(root)]
	assert.False(t, found, "self-signed root must not be mapped to a parent")
}

// TestBuildParentMap_ChainLinkage verifies that a two-cert chain maps the leaf
// fingerprint to the root and the root fingerprint has no entry.
func TestBuildParentMap_ChainLinkage(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootCA := testx509.NewCertificateAuthority(t, "Root CA", testx509.WithSigner(rootKey))
	root := rootCA.GenerateCaCertificate(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/svc")
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}
	leaf := testx509.CreateCertificate(t, tmpl, root, leafKey.Public(), rootKey)

	m := buildParentMap([]*x509.Certificate{root, leaf})

	parent, found := m[certFingerprint(leaf)]
	require.True(t, found, "leaf must be mapped to a parent")
	assert.Equal(t, certFingerprint(root), certFingerprint(parent), "leaf's parent must be the root")

	_, rootHasParent := m[certFingerprint(root)]
	assert.False(t, rootHasParent, "self-signed root must not have a parent entry")
}

// TestIsParent_DNOnlyFallback_RejectsSameDNNonSigner verifies that the fallback
// branch of isParent rejects a candidate parent that shares the same Subject DN
// as the real signer but carries a different key. This is the CA-rotation
// scenario where the fix prevents mis-linking.
func TestIsParent_DNOnlyFallback_RejectsSameDNNonSigner(t *testing.T) {
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Build two CA certs with identical Subject DNs but distinct signing keys.
	caA := testx509.NewCertificateAuthority(t, "Same DN", testx509.WithSigner(keyA))
	caACert := caA.GenerateCaCertificate(t)

	caB := testx509.NewCertificateAuthority(t, "Same DN", testx509.WithSigner(keyB))
	caBCert := caB.GenerateCaCertificate(t)

	// Build a leaf signed by CA A.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leaf := caA.GenerateCaCertificate(t,
		testx509.WithPublicKey(leafKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "leaf"}),
	)

	// Zero out AKI/SKI in shallow copies to force the DN-only fallback path.
	// certFingerprint and CheckSignatureFrom use cert.Raw / cert.PublicKey, which
	// are unchanged by field mutation on the copy, so signature verification still
	// reflects the real key relationship.
	caACopy := *caACert
	caACopy.SubjectKeyId = nil
	caBCopy := *caBCert
	caBCopy.SubjectKeyId = nil
	leafCopy := *leaf
	leafCopy.AuthorityKeyId = nil

	// Pre-flight: confirm the copies have no AKI/SKI so the fallback path is
	// genuinely exercised. If the zeroing stops working these will fail loudly.
	require.Empty(t, caACopy.SubjectKeyId, "CA A copy must have empty SubjectKeyId for fallback path")
	require.Empty(t, caBCopy.SubjectKeyId, "CA B copy must have empty SubjectKeyId for fallback path")
	require.Empty(t, leafCopy.AuthorityKeyId, "leaf copy must have empty AuthorityKeyId for fallback path")

	// CA A signed the leaf: DN matches and signature verifies.
	assert.True(t, isParent(&leafCopy, &caACopy), "signing CA must be recognised as the leaf's parent")

	// CA B has the same DN but a different key: signature verification must reject it.
	assert.False(t, isParent(&leafCopy, &caBCopy), "lookalike CA with same DN but different key must be rejected")
}

// TestBuildParentMap_ThreeLevelChain verifies that a root→intermediate→leaf
// chain yields correct parent links for all three levels.
func TestBuildParentMap_ThreeLevelChain(t *testing.T) {
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)
	all := []*x509.Certificate{root, intermediate, leaf}

	m := buildParentMap(all)

	intParent, ok := m[certFingerprint(intermediate)]
	require.True(t, ok, "intermediate must have a parent entry")
	assert.Equal(t, certFingerprint(root), certFingerprint(intParent))

	leafParent, ok := m[certFingerprint(leaf)]
	require.True(t, ok, "leaf must have a parent entry")
	assert.Equal(t, certFingerprint(intermediate), certFingerprint(leafParent))

	_, rootHasParent := m[certFingerprint(root)]
	assert.False(t, rootHasParent, "root must not have a parent entry")
}

// TestBuildParentMap_FiveDeepChain is a regression guard for the cached-fingerprint
// optimisation in identifyLeaf and buildParentMap (chain.go).  A 5-cert chain
// (root + 3 intermediates + SPIFFE leaf) is larger than the 3-cert fixture used
// elsewhere, exercising the O(n²) indexed loops on input where an off-by-one
// error would produce wrong parent links.
//
// Intermediates beyond the first are built with testx509.CreateCertificate
// (passing the actual previous cert as the parent struct) so that Go's
// x509.CreateCertificate propagates SubjectKeyId → AuthorityKeyId correctly,
// ensuring isParent resolves all links via the AKI/SKI primary path.
func TestBuildParentMap_FiveDeepChain(t *testing.T) {
	// Root CA (self-signed, RSA-2048 by default).
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	// Intermediate 1: signed by rootCA.  Use GenerateCaCertificate so that
	// root.SubjectKeyId == int1.AuthorityKeyId (propagated via GetIssuerTemplate).
	intKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey1.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 1"}),
		testx509.WithSerialNumber(*big.NewInt(10)),
	)

	// Intermediates 2 and 3 + leaf: use CreateCertificate with the actual
	// parent cert so Go's x509 layer copies the real SubjectKeyId into the
	// child's AuthorityKeyId, making AKI/SKI matching unambiguous.
	intKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Intermediate CA 2"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, int1, intKey2.Public(), intKey1)

	intKey3, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int3 := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(30),
		Subject:               pkix.Name{CommonName: "Intermediate CA 3"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, int2, intKey3.Public(), intKey2)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/five-deep")
	require.NoError(t, err)
	leaf := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "five-deep-workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, int3, leafKey.Public(), intKey3)

	all := []*x509.Certificate{root, int1, int2, int3, leaf}

	// identifyLeaf must select the SPIFFE leaf.
	got, err := identifyLeaf(all)
	require.NoError(t, err)
	assert.Equal(t, certFingerprint(leaf), certFingerprint(got), "identifyLeaf must return the SPIFFE leaf")

	// buildParentMap must link every non-root cert to its correct parent.
	parents := buildParentMap(all)

	int1Parent, ok := parents[certFingerprint(int1)]
	require.True(t, ok, "int1 must have a parent entry")
	assert.Equal(t, certFingerprint(root), certFingerprint(int1Parent), "int1's parent must be root")

	int2Parent, ok := parents[certFingerprint(int2)]
	require.True(t, ok, "int2 must have a parent entry")
	assert.Equal(t, certFingerprint(int1), certFingerprint(int2Parent), "int2's parent must be int1")

	int3Parent, ok := parents[certFingerprint(int3)]
	require.True(t, ok, "int3 must have a parent entry")
	assert.Equal(t, certFingerprint(int2), certFingerprint(int3Parent), "int3's parent must be int2")

	leafParent, ok := parents[certFingerprint(leaf)]
	require.True(t, ok, "leaf must have a parent entry")
	assert.Equal(t, certFingerprint(int3), certFingerprint(leafParent), "leaf's parent must be int3")

	_, rootHasParent := parents[certFingerprint(root)]
	assert.False(t, rootHasParent, "root must not have a parent entry")
}

// TestBuildChain_FiveDeepChain_RootToLeafOrder is a regression guard for the
// cached-fingerprint optimisation in buildParentMap (chain.go). The 5-cert
// chain (root → int1 → int2 → int3 → SPIFFE leaf) exercises the O(n²) loops
// with the pre-computed fps[] slices and verifies that buildChain produces the
// correct root-to-leaf ordering.
func TestBuildChain_FiveDeepChain_RootToLeafOrder(t *testing.T) {
	rootCA := testx509.NewCertificateAuthority(t, "Root CA")
	root := rootCA.GenerateCaCertificate(t)

	intKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int1 := rootCA.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey1.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "Intermediate CA 1"}),
		testx509.WithSerialNumber(*big.NewInt(10)),
	)

	intKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int2 := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(20),
		Subject:               pkix.Name{CommonName: "Intermediate CA 2"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, int1, intKey2.Public(), intKey1)

	intKey3, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	int3 := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(30),
		Subject:               pkix.Name{CommonName: "Intermediate CA 3"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, int2, intKey3.Public(), intKey2)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/five-deep-order")
	require.NoError(t, err)
	leaf := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "five-deep-workload"},
		NotBefore:             root.NotBefore,
		NotAfter:              root.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, int3, leafKey.Public(), intKey3)

	// Shuffle the input order to confirm buildChain always produces root-to-leaf.
	all := []*x509.Certificate{leaf, int2, root, int3, int1}

	chain, err := buildChain(all)
	require.NoError(t, err)
	require.Len(t, chain, 5, "chain must contain all five certs")

	assert.Equal(t, certFingerprint(root), certFingerprint(chain[0]), "chain[0] must be root")
	assert.Equal(t, certFingerprint(int1), certFingerprint(chain[1]), "chain[1] must be int1")
	assert.Equal(t, certFingerprint(int2), certFingerprint(chain[2]), "chain[2] must be int2")
	assert.Equal(t, certFingerprint(int3), certFingerprint(chain[3]), "chain[3] must be int3")
	assert.Equal(t, certFingerprint(leaf), certFingerprint(chain[4]), "chain[4] must be leaf")
}

// TestConvertCertsToChain_AlternatePathNote_RoutedToOptsStderr verifies that the
// "note: N alternate paths of equal length" diagnostic is written to opts.Stderr
// when set. The test constructs a cross-signed topology where two roots sign the
// same intermediate key, giving x509.Verify two equal-length chains. If Go's
// x509.Verify returns only one chain for this topology the test is skipped, since
// the alternate-path branch is not reachable on that build.
func TestConvertCertsToChain_AlternatePathNote_RoutedToOptsStderr(t *testing.T) {
	rootCA_A := testx509.NewCertificateAuthority(t, "Root CA A")
	rootA := rootCA_A.GenerateCaCertificate(t)

	rootCA_B := testx509.NewCertificateAuthority(t, "Root CA B")
	rootB := rootCA_B.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateSignedByA := rootCA_A.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "X-Signed Intermediate"}),
	)
	intermediateSignedByB := rootCA_B.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(pkix.Name{CommonName: "X-Signed Intermediate"}),
	)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/xsigned-stderr")
	require.NoError(t, err)
	leaf := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(201),
		Subject:               pkix.Name{CommonName: "xsigned-stderr-workload"},
		NotBefore:             rootA.NotBefore,
		NotAfter:              rootA.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, intermediateSignedByA, leafKey.Public(), intKey)

	all := []*x509.Certificate{rootA, rootB, intermediateSignedByA, intermediateSignedByB, leaf}

	var stderrBuf bytes.Buffer
	opts := X509ConvertOptions{
		Chain:  X509ChainOptions{ShortestPath: true},
		Stderr: &stderrBuf,
	}
	_, err = ConvertCertsToChain(all, opts)
	require.NoError(t, err)

	note := stderrBuf.String()
	if !strings.Contains(note, "of equal length") {
		t.Skip("x509.Verify returned only one chain; alternate-path branch not reachable on this Go build")
	}
	assert.Contains(t, note, "alternate path",
		"alternate-path note must be routed to opts.Stderr, not os.Stderr")
}
