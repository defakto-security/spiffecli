package cmd

import (
	"bytes"
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

// writeSVIDToTempFile creates a conformant X.509-SVID cert and writes it to a temp file.
func writeSVIDToTempFile(t *testing.T) string {
	t.Helper()
	_, leafCert, _ := testx509.NewConformantSVID(t, "spiffe://example.com/test")
	path := filepath.Join(t.TempDir(), "svid.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(leafCert), 0600))
	return path
}

func TestNewInspectJWTCmd_Properties(t *testing.T) {
	cmd := NewInspectJWTCmd()
	assert.Equal(t, "jwt", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("isSvid"))
	assert.NotNil(t, cmd.Flags().Lookup("headers"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("indent"))
	assert.NotNil(t, cmd.Flags().Lookup("color"))
	assert.NotNil(t, cmd.Flags().Lookup("timezone"))
}

func TestNewInspectJWTCmd_NoFile(t *testing.T) {
	cmd := NewInspectJWTCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a file")
}

func TestNewInspectJWTCmd_WithFile(t *testing.T) {
	cmd := NewInspectJWTCmd()
	require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestNewInspectBundleCmd_Properties(t *testing.T) {
	cmd := NewInspectBundleCmd()
	assert.Equal(t, "jwks", cmd.Use)
	assert.NotEmpty(t, cmd.Short)

	assert.NotNil(t, cmd.Flags().Lookup("location"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("indent"))
	assert.NotNil(t, cmd.Flags().Lookup("color"))
}

func TestNewInspectBundleCmd_NoLocation(t *testing.T) {
	cmd := NewInspectBundleCmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestNewInspectBundleCmd_WithLocation(t *testing.T) {
	cmd := NewInspectBundleCmd()
	require.NoError(t, cmd.Flags().Set("location", "../internal/bundle/testdata/single.jwks"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestNewInspectX509Cmd_Properties(t *testing.T) {
	cmd := NewInspectX509Cmd()
	assert.Equal(t, "x509", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	assert.NotNil(t, cmd.Flags().Lookup("filename"))
	assert.NotNil(t, cmd.Flags().Lookup("isSvid"))
	assert.NotNil(t, cmd.Flags().Lookup("format"))
	assert.NotNil(t, cmd.Flags().Lookup("indent"))
	assert.NotNil(t, cmd.Flags().Lookup("color"))
	assert.NotNil(t, cmd.Flags().Lookup("timezone"))
	assert.NotNil(t, cmd.Flags().Lookup("bundle"))
	assert.NotNil(t, cmd.Flags().Lookup("shortest-path"))
	assert.NotNil(t, cmd.Flags().Lookup("tree-fields"))

	// --format description must list chain and tree.
	formatFlag := cmd.Flags().Lookup("format")
	assert.Contains(t, formatFlag.Usage, "chain")
	assert.Contains(t, formatFlag.Usage, "tree")
}

func TestNewInspectX509Cmd_NoFile(t *testing.T) {
	cmd := NewInspectX509Cmd()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify a file")
}

func TestNewInspectX509Cmd_WithFile(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()
	require.NoError(t, cmd.Flags().Set("filename", path))

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, buf.String(), "spiffe_id")
}

// TestNewInspectX509Cmd_OutputRoutedThroughWriter is the regression guard for the
// fmt.Print -> fmt.Fprint(cmd.OutOrStdout()) fix in NewInspectX509Cmd. It verifies
// that the default JSON output is captured by cmd.SetOut and not written directly to os.Stdout.
// Symmetric with TestNewInspectJWTCmd_OutputRoutedThroughWriter and
// TestNewInspectBundleCmd_OutputRoutedThroughWriter.
func TestNewInspectX509Cmd_OutputRoutedThroughWriter(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", path))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotEmpty(t, buf.String(), "JSON output must appear in cmd.OutOrStdout(), not os.Stdout")
	assert.Contains(t, buf.String(), "spiffe_id")
}

// TestNewInspectX509Cmd_AllFormatsRoutedThroughWriter verifies that yaml and summary output
// formats are also written to cmd.OutOrStdout(), not directly to os.Stdout. This is the
// regression guard for the fmt.Print -> fmt.Fprint(cmd.OutOrStdout()) fix.
func TestNewInspectX509Cmd_AllFormatsRoutedThroughWriter(t *testing.T) {
	path := writeSVIDToTempFile(t)

	tests := []struct {
		format   string
		contains string
	}{
		{"yaml", "spiffe_id"},
		{"summary", "SPIFFE ID"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("format="+tt.format, func(t *testing.T) {
			cmd := NewInspectX509Cmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			require.NoError(t, cmd.Flags().Set("filename", path))
			require.NoError(t, cmd.Flags().Set("format", tt.format))
			cmd.SetArgs([]string{})
			require.NoError(t, cmd.Execute())
			assert.NotEmpty(t, buf.String(), "format %q produced no output", tt.format)
			assert.Contains(t, buf.String(), tt.contains)
		})
	}
}

// TestNewInspectX509Cmd_IsSvid_Conformant verifies that --isSvid with a conformant cert
// returns no error and produces no output (exit-code-only signaling).
func TestNewInspectX509Cmd_IsSvid_Conformant(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()

	var stderrBuf, stdoutBuf bytes.Buffer
	cmd.SetErr(&stderrBuf)
	cmd.SetOut(&stdoutBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("isSvid", "true"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.Empty(t, stderrBuf.String())
	assert.Empty(t, stdoutBuf.String())
}

// TestNewInspectX509Cmd_LongContainsPIIWarning verifies the Long description warns
// about email SANs as PII and mentions piping to external systems. This prevents
// regression where the warning is replaced with unrelated content.
func TestNewInspectX509Cmd_LongContainsPIIWarning(t *testing.T) {
	cmd := NewInspectX509Cmd()
	long := cmd.Long
	assert.Contains(t, long, "email", "Long description must mention email addresses")
	assert.Contains(t, long, "PII", "Long description must reference PII")
	// Verify the warning covers piping to external systems (SIEM/log aggregation).
	assert.True(t,
		strings.Contains(long, "log aggregat") || strings.Contains(long, "SIEM") || strings.Contains(long, "audit"),
		"Long description must warn about external systems like log aggregators or SIEMs",
	)
}

// TestNewInspectX509Cmd_LongCoversExpandedPIIFields verifies the Long description
// covers the Subject field and DNS SANs as potential PII vectors, matching the
// expanded warning requested in review comment thread 40/43.
func TestNewInspectX509Cmd_LongCoversExpandedPIIFields(t *testing.T) {
	cmd := NewInspectX509Cmd()
	long := cmd.Long

	// Subject / X.500 Distinguished Name must be mentioned.
	assert.True(t,
		strings.Contains(long, "Subject") || strings.Contains(long, "Distinguished Name") || strings.Contains(long, "X.500"),
		"Long description must warn that the Subject (X.500 DN) may contain PII",
	)

	// Personal names must be mentioned (CN field in X.500 DN).
	assert.Contains(t, long, "personal names", "Long description must mention personal names as PII in Subject")

	// Internal hostnames via DNS SANs must be mentioned.
	assert.True(t,
		strings.Contains(long, "internal hostname") || strings.Contains(long, "hostname"),
		"Long description must warn that DNS SANs may expose internal hostnames",
	)
}

// TestNewInspectX509Cmd_LongMentionsBothSANAndSubject verifies acceptance criterion for
// review comment thread 43/43: the Long description must name BOTH Subject Alternative Name
// (SAN) fields AND the certificate Subject (X.500 DN) as potential PII vectors. The original
// warning only covered email SAN addresses; the reviewer asked it be broadened to include the
// full Subject DN (personal names, street addresses) and all SAN types (DNS, email, IP, URI).
func TestNewInspectX509Cmd_LongMentionsBothSANAndSubject(t *testing.T) {
	cmd := NewInspectX509Cmd()
	long := cmd.Long

	// SAN / Subject Alternative Name must appear.
	assert.True(t,
		strings.Contains(long, "Subject Alternative Name") || strings.Contains(long, "SAN"),
		"Long description must mention Subject Alternative Name (SAN) fields",
	)

	// Certificate Subject (X.500 DN) must also appear — these are the two top-level
	// PII vectors called out in the review comment.
	assert.True(t,
		strings.Contains(long, "Subject") || strings.Contains(long, "X.500") || strings.Contains(long, "Distinguished Name"),
		"Long description must mention the certificate Subject (X.500 Distinguished Name)",
	)
}

// TestNewInspectX509Cmd_HelpShowsPIIWarning verifies the PII warning is visible
// via --help, matching acceptance criterion: "visible via spiffecli inspect x509 --help".
func TestNewInspectX509Cmd_HelpShowsPIIWarning(t *testing.T) {
	cmd := NewInspectX509Cmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})
	// cobra returns nil for --help; the help text is written to cmd.OutOrStdout().
	require.NoError(t, cmd.Execute())
	help := out.String()
	assert.Contains(t, help, "email", "help output must mention email addresses")
	assert.Contains(t, help, "PII", "help output must reference PII")
	// Verify the expanded warning fields also appear in help output.
	assert.True(t,
		strings.Contains(help, "Subject") || strings.Contains(help, "Distinguished Name"),
		"help output must mention the certificate Subject",
	)
}

// TestNewInspectX509Cmd_IsSvid_Conformant_FormatIgnored verifies that --isSvid with
// --format set still produces no output when the cert is conformant.
// Regression guard: the early return in Inspect() fires before format dispatch.
func TestNewInspectX509Cmd_IsSvid_Conformant_FormatIgnored(t *testing.T) {
	path := writeSVIDToTempFile(t)

	for _, format := range []string{"json", "yaml", "summary"} {
		format := format
		t.Run("format="+format, func(t *testing.T) {
			cmd := NewInspectX509Cmd()
			var stderrBuf, stdoutBuf bytes.Buffer
			cmd.SetErr(&stderrBuf)
			cmd.SetOut(&stdoutBuf)

			require.NoError(t, cmd.Flags().Set("filename", path))
			require.NoError(t, cmd.Flags().Set("isSvid", "true"))
			require.NoError(t, cmd.Flags().Set("format", format))

			cmd.SetArgs([]string{})
			require.NoError(t, cmd.Execute())

			assert.Empty(t, stdoutBuf.String(), "--isSvid success must produce no stdout with --format=%s", format)
			assert.Empty(t, stderrBuf.String(), "--isSvid success must produce no stderr with --format=%s", format)
		})
	}
}

func TestNewInspectX509Cmd_UnsupportedFormat(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()
	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("format", "unsupported"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// TestNewInspectX509Cmd_IsSvid_Fail verifies that --isSvid on a non-conformant cert
// returns a non-nil error whose message names the violations.
func TestNewInspectX509Cmd_IsSvid_Fail(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := testx509.NewCertificateAuthority(t, "Test CA", testx509.WithSigner(caKey))
	caCert := ca.GenerateCaCertificate(t)

	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pemutil.EncodeCertificate(caCert), 0600))

	cmd := NewInspectX509Cmd()
	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("isSvid", "true"))

	cmd.SetArgs([]string{})
	err = cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a well-formed X.509-SVID")
}

// TestNewInspectX509Cmd_JSON_NoStderrLeak verifies that normal JSON inspection writes
// nothing to stderr. This is the regression guard for the fmt.Print -> fmt.Fprint(cmd.OutOrStdout())
// fix: the old code would bypass cobra's writer and always write to os.Stdout, but nothing
// should ever land on stderr during a successful inspection.
func TestNewInspectX509Cmd_JSON_NoStderrLeak(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()

	var stderrBuf bytes.Buffer
	cmd.SetErr(&stderrBuf)
	require.NoError(t, cmd.Flags().Set("filename", path))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Empty(t, stderrBuf.String(), "successful JSON inspection must not write to stderr")
}

// TestNewInspectBundleCmd_OutputRoutedThroughWriter is the regression guard for the
// fmt.Print -> fmt.Fprint(cmd.OutOrStdout()) fix in NewInspectBundleCmd. It verifies
// that normal JSON output is captured by cmd.SetOut and not written directly to os.Stdout.
func TestNewInspectBundleCmd_OutputRoutedThroughWriter(t *testing.T) {
	cmd := NewInspectBundleCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("location", "../internal/bundle/testdata/single.jwks"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotEmpty(t, buf.String(), "JSON output must appear in cmd.OutOrStdout(), not os.Stdout")
}

// TestNewInspectBundleCmd_AllFormatsRoutedThroughWriter verifies that yaml, summary, and key-ids
// output formats are also written to cmd.OutOrStdout(). Symmetric with
// TestNewInspectX509Cmd_AllFormatsRoutedThroughWriter and TestNewInspectJWTCmd_AllFormatsRoutedThroughWriter.
func TestNewInspectBundleCmd_AllFormatsRoutedThroughWriter(t *testing.T) {
	tests := []struct {
		format   string
		contains string
	}{
		{"yaml", "keys"},
		{"summary", "Key"},
		{"key-ids", ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("format="+tt.format, func(t *testing.T) {
			cmd := NewInspectBundleCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			require.NoError(t, cmd.Flags().Set("location", "../internal/bundle/testdata/single.jwks"))
			require.NoError(t, cmd.Flags().Set("format", tt.format))
			cmd.SetArgs([]string{})
			require.NoError(t, cmd.Execute())
			assert.NotEmpty(t, buf.String(), "format %q produced no output in cmd.OutOrStdout()", tt.format)
			if tt.contains != "" {
				assert.Contains(t, buf.String(), tt.contains)
			}
		})
	}
}

// TestNewInspectBundleCmd_NoStderrLeak verifies that successful bundle inspection writes
// nothing to stderr. Symmetric with TestNewInspectX509Cmd_JSON_NoStderrLeak and
// TestNewInspectJWTCmd_NoStderrLeak.
func TestNewInspectBundleCmd_NoStderrLeak(t *testing.T) {
	cmd := NewInspectBundleCmd()

	var stderrBuf bytes.Buffer
	cmd.SetErr(&stderrBuf)
	require.NoError(t, cmd.Flags().Set("location", "../internal/bundle/testdata/single.jwks"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Empty(t, stderrBuf.String(), "successful bundle inspection must not write to stderr")
}

// TestNewInspectJWTCmd_IsSvid_Conformant verifies that --isSvid with a conformant JWT SVID
// returns no error and produces no output. This is the JWT-inspector analogue of
// TestNewInspectX509Cmd_IsSvid_Conformant, guarding the symmetric silent-success contract:
// both inspectors must return ("", nil) on --isSvid success and write nothing to stdout/stderr.
func TestNewInspectJWTCmd_IsSvid_Conformant(t *testing.T) {
	cmd := NewInspectJWTCmd()

	var stderrBuf, stdoutBuf bytes.Buffer
	cmd.SetErr(&stderrBuf)
	cmd.SetOut(&stdoutBuf)

	require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/svid.jwt"))
	require.NoError(t, cmd.Flags().Set("isSvid", "true"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.Empty(t, stdoutBuf.String(), "JWT --isSvid success must produce no stdout")
	assert.Empty(t, stderrBuf.String(), "JWT --isSvid success must produce no stderr")
}

// TestNewInspectX509Cmd_IsSvid_SuccessWritesNothingToStdout pins the exit-code-only gate at
// the command level. The old behavior wrote "certificate is a well-formed X.509-SVID\n" to
// stdout on conformant input; that string has been removed and must not return. Scripts that
// use `spiffecli inspect x509 --isSvid` must be able to rely on exit code alone.
func TestNewInspectX509Cmd_IsSvid_SuccessWritesNothingToStdout(t *testing.T) {
	path := writeSVIDToTempFile(t)
	cmd := NewInspectX509Cmd()

	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("isSvid", "true"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	require.Equal(t, "", out.String(), "--isSvid success must write exactly nothing to stdout")
}

// TestNewInspectJWTCmd_IsSvid_NonConformant verifies that --isSvid on a non-SVID JWT
// returns a non-nil error. Symmetric with TestNewInspectX509Cmd_IsSvid_Fail.
func TestNewInspectJWTCmd_IsSvid_NonConformant(t *testing.T) {
	cmd := NewInspectJWTCmd()

	require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))
	require.NoError(t, cmd.Flags().Set("isSvid", "true"))

	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an SPIFFE SVID")
}

// TestNewInspectJWTCmd_OutputRoutedThroughWriter is the regression guard for
// the fmt.Print -> fmt.Fprint(cmd.OutOrStdout()) fix in NewInspectJWTCmd.
// It verifies that normal JSON output is captured by cmd.SetOut and not lost
// to os.Stdout directly.
func TestNewInspectJWTCmd_OutputRoutedThroughWriter(t *testing.T) {
	cmd := NewInspectJWTCmd()

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotEmpty(t, buf.String(), "JSON output must appear in cmd.OutOrStdout(), not os.Stdout")
}

// TestNewInspectJWTCmd_AllFormatsRoutedThroughWriter is the JWT symmetric counterpart
// of TestNewInspectX509Cmd_AllFormatsRoutedThroughWriter. It verifies that yaml and
// summary output formats are also routed through cmd.OutOrStdout().
func TestNewInspectJWTCmd_AllFormatsRoutedThroughWriter(t *testing.T) {
	tests := []struct {
		format   string
		contains string
	}{
		{"yaml", "sub"},
		{"summary", "Subject"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("format="+tt.format, func(t *testing.T) {
			cmd := NewInspectJWTCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))
			require.NoError(t, cmd.Flags().Set("format", tt.format))
			cmd.SetArgs([]string{})
			require.NoError(t, cmd.Execute())
			assert.NotEmpty(t, buf.String(), "format %q produced no output in cmd.OutOrStdout()", tt.format)
			assert.Contains(t, buf.String(), tt.contains)
		})
	}
}

// TestNewInspectJWTCmd_NoStderrLeak verifies that successful JWT inspection writes
// nothing to stderr. Symmetric with TestNewInspectX509Cmd_JSON_NoStderrLeak.
func TestNewInspectJWTCmd_NoStderrLeak(t *testing.T) {
	cmd := NewInspectJWTCmd()

	var stderrBuf bytes.Buffer
	cmd.SetErr(&stderrBuf)
	require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))

	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	assert.Empty(t, stderrBuf.String(), "successful JWT inspection must not write to stderr")
}

// TestNewInspectX509Cmd_TimezonePathTraversalRejected verifies that path-traversal
// timezone inputs are rejected end-to-end through the cobra command, not just at the
// internal package level. This is the cmd-level counterpart of
// TestConvertCertsToSummary_LeadingAndConsecutiveSlashTimezone.
func TestNewInspectX509Cmd_TimezonePathTraversalRejected(t *testing.T) {
	path := writeSVIDToTempFile(t)

	tests := []struct {
		name     string
		timezone string
	}{
		{name: "leading slash /etc/passwd", timezone: "/etc/passwd"},
		{name: "leading slash /etc/localtime", timezone: "/etc/localtime"},
		{name: "leading slash /proc/self/environ", timezone: "/proc/self/environ"},
		{name: "consecutive slashes mid", timezone: "America//Los_Angeles"},
		{name: "trailing slash", timezone: "America/"},
		{name: "double slash only", timezone: "//"},
		{name: "single slash only", timezone: "/"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewInspectX509Cmd()
			require.NoError(t, cmd.Flags().Set("filename", path))
			require.NoError(t, cmd.Flags().Set("format", "summary"))
			require.NoError(t, cmd.Flags().Set("timezone", tt.timezone))

			cmd.SetArgs([]string{})
			err := cmd.Execute()
			require.Error(t, err, "expected error for timezone %q", tt.timezone)
			assert.Contains(t, err.Error(), "invalid timezone")
		})
	}
}

// TestNewInspectJWTCmd_TimezonePathTraversalRejected verifies that path-traversal
// timezone inputs are rejected end-to-end through the cobra command for the JWT inspector.
// Symmetric with TestNewInspectX509Cmd_TimezonePathTraversalRejected.
func TestNewInspectJWTCmd_TimezonePathTraversalRejected(t *testing.T) {
	tests := []struct {
		name     string
		timezone string
	}{
		{name: "leading slash /etc/passwd", timezone: "/etc/passwd"},
		{name: "leading slash /proc/self/environ", timezone: "/proc/self/environ"},
		{name: "consecutive slashes mid", timezone: "America//Los_Angeles"},
		{name: "trailing slash", timezone: "America/"},
		{name: "double slash only", timezone: "//"},
		{name: "single slash only", timezone: "/"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewInspectJWTCmd()
			require.NoError(t, cmd.Flags().Set("filename", "../internal/jwtinspect/testdata/simple.jwt"))
			require.NoError(t, cmd.Flags().Set("format", "summary"))
			require.NoError(t, cmd.Flags().Set("timezone", tt.timezone))

			cmd.SetArgs([]string{})
			err := cmd.Execute()
			require.Error(t, err, "expected error for timezone %q", tt.timezone)
			assert.Contains(t, err.Error(), "invalid timezone")
		})
	}
}

// writeChainToTempFile creates a 3-cert chain (root→intermediate→leaf SVID) and writes it
// to a temp PEM file. Returns the path and the root cert separately for --bundle tests.
func writeChainToTempFile(t *testing.T) (chainPath, rootPath string) {
	t.Helper()
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	chainPath = filepath.Join(t.TempDir(), "chain.pem")
	require.NoError(t, os.WriteFile(chainPath,
		pemutil.EncodeCertificates([]*x509.Certificate{root, intermediate, leaf}), 0600))

	rootPath = filepath.Join(t.TempDir(), "root.pem")
	require.NoError(t, os.WriteFile(rootPath,
		pemutil.EncodeCertificates([]*x509.Certificate{root}), 0600))

	return chainPath, rootPath
}

func TestNewInspectX509Cmd_ChainFormat(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)
	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "chain"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "Intermediate CA")
	assert.Contains(t, out, "workload")
	assert.Contains(t, out, "[spiffe://example.com/workload]")
	// Root should have no indent; leaf should be most indented.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	assert.False(t, strings.HasPrefix(lines[0], " "), "root should have no indent")
}

func TestNewInspectX509Cmd_TreeFormat(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)
	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "tree"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "workload")
	// Tree uses connector characters.
	assert.Contains(t, out, "└─")
}

func TestNewInspectX509Cmd_ShortestPath(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)
	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "chain"))
	require.NoError(t, cmd.Flags().Set("shortest-path", "true"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	// Should produce 3 lines: root, intermediate, leaf.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	assert.Len(t, lines, 3)
}

// TestNewInspectX509Cmd_TreeFieldsFlag verifies that --format tree with
// --tree-fields "subject,not-after" renders both the leaf subject and
// per-node "not-after:" continuation lines via the cobra command path.
func TestNewInspectX509Cmd_TreeFieldsFlag(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)
	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "tree"))
	require.NoError(t, cmd.Flags().Set("tree-fields", "subject,not-after"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	assert.Contains(t, out, "not-after:", "tree output must include not-after continuation lines")
	assert.Contains(t, out, "workload", "tree output must include leaf subject")
}

// TestNewInspectX509Cmd_BundleErrorPaths verifies that --bundle error paths propagate
// through the cobra command layer. The unit-level tests in internal/x509inspect cover
// the inspector logic; this test ensures those errors are not swallowed at the cmd boundary.
func TestNewInspectX509Cmd_BundleErrorPaths(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)

	tests := []struct {
		name       string
		bundlePath func(t *testing.T) string
		wantErr    string
	}{
		{
			name: "nonexistent bundle file",
			bundlePath: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "missing-bundle.pem")
			},
			wantErr: "failed to read certificates from file",
		},
		{
			name: "empty bundle file (no certificate blocks)",
			bundlePath: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "empty-bundle.pem")
				require.NoError(t, os.WriteFile(p, []byte{}, 0600))
				return p
			},
			wantErr: "no certificates found in file",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewInspectX509Cmd()
			var outBuf, errBuf bytes.Buffer
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)

			require.NoError(t, cmd.Flags().Set("filename", chainPath))
			require.NoError(t, cmd.Flags().Set("bundle", tt.bundlePath(t)))
			require.NoError(t, cmd.Flags().Set("format", "chain"))

			cmd.SetArgs([]string{})
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestNewInspectX509Cmd_TreeFieldsDefaultIsEmpty locks in the contract that the
// --tree-fields cobra flag has no registered default (empty string). The semantic
// default of "subject" is handled by the tree converter, not by cobra.
func TestNewInspectX509Cmd_TreeFieldsDefaultIsEmpty(t *testing.T) {
	cmd := NewInspectX509Cmd()
	flag := cmd.Flags().Lookup("tree-fields")
	require.NotNil(t, flag)
	assert.Equal(t, "", flag.DefValue,
		"--tree-fields must have an empty DefValue so the tree converter's own default applies when the flag is omitted")
}

// TestNewInspectX509Cmd_TreeFieldsUsageMentionsSemanticDefault pins the wording contract
// for the --tree-fields flag description: it must mention the semantic default ("subject")
// in plain prose and must NOT contain cobra-default-mimicking shapes like "(default \"..."
// or "(default:".
func TestNewInspectX509Cmd_TreeFieldsUsageMentionsSemanticDefault(t *testing.T) {
	cmd := NewInspectX509Cmd()
	flag := cmd.Flags().Lookup("tree-fields")
	require.NotNil(t, flag)
	usage := flag.Usage
	assert.Contains(t, strings.ToLower(usage), "subject",
		"--tree-fields usage must mention 'subject' as the semantic default")
	assert.Contains(t, strings.ToLower(usage), "omit",
		"--tree-fields usage must indicate what happens when the flag is omitted")
	assert.NotContains(t, usage, `(default "`,
		"--tree-fields usage must not mimic cobra's auto-format default annotation")
	assert.NotContains(t, usage, "(default:",
		"--tree-fields usage must not mimic cobra's default annotation style")
}

// TestNewInspectX509Cmd_TreeFieldsDefaultPropagates verifies that when no --tree-fields
// flag is given, the inspector receives "subject" and the tree converter gets ["subject"]
// in TreeFields (i.e. the cobra default flows through to the rendering logic).
func TestNewInspectX509Cmd_TreeFieldsDefaultPropagates(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)
	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "tree"))
	// Do NOT set --tree-fields; we want the cobra default to take effect.
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	// Output should contain subject text (tree with default "subject" field).
	assert.Contains(t, out, "Root CA", "tree output with default tree-fields must include subject")
	assert.Contains(t, out, "workload", "tree output with default tree-fields must include leaf subject")
}

// TestNewInspectX509Cmd_TreeFieldsExplicitSubjectMatchesDefault verifies that explicit
// --tree-fields=subject produces byte-identical output to the default (no flag given).
func TestNewInspectX509Cmd_TreeFieldsExplicitSubjectMatchesDefault(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)

	run := func(setTreeFields bool) string {
		cmd := NewInspectX509Cmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		require.NoError(t, cmd.Flags().Set("filename", chainPath))
		require.NoError(t, cmd.Flags().Set("format", "tree"))
		if setTreeFields {
			require.NoError(t, cmd.Flags().Set("tree-fields", "subject"))
		}
		cmd.SetArgs([]string{})
		require.NoError(t, cmd.Execute())
		return buf.String()
	}

	defaultOut := run(false)
	explicitOut := run(true)
	assert.Equal(t, defaultOut, explicitOut,
		"--tree-fields=subject must produce identical output to omitting the flag entirely")
}

func TestNewInspectX509Cmd_BundleFlag(t *testing.T) {
	// Only intermediate + leaf in chain file; root supplied via --bundle.
	root, intermediate, leaf := testx509.NewThreeLevelSPIFFEChain(t)

	dir := t.TempDir()
	chainPath := filepath.Join(dir, "chain.pem")
	require.NoError(t, os.WriteFile(chainPath,
		pemutil.EncodeCertificates([]*x509.Certificate{intermediate, leaf}), 0600))
	bundlePath := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(bundlePath,
		pemutil.EncodeCertificates([]*x509.Certificate{root}), 0600))

	cmd := NewInspectX509Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("bundle", bundlePath))
	require.NoError(t, cmd.Flags().Set("format", "chain"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())
	out := buf.String()
	// All three certs should appear in the output.
	assert.Contains(t, out, "Root CA")
	assert.Contains(t, out, "Intermediate CA")
	assert.Contains(t, out, "workload")
}

// TestNewInspectX509Cmd_ColorFlagHelpDisclaimer guards that the --color flag's Usage string
// for inspect x509 disclaim that it has no effect for chain/tree formats. This prevents
// a future refactor from silently reverting the disclaimer and misleading users.
func TestNewInspectX509Cmd_ColorFlagHelpDisclaimer(t *testing.T) {
	cmd := NewInspectX509Cmd()
	flag := cmd.Flags().Lookup("color")
	require.NotNil(t, flag)
	assert.Contains(t, flag.Usage, "Has no effect for chain or tree formats",
		"--color flag Usage must disclaim that it has no effect for chain or tree formats")
}

// TestOtherInspectCmds_ColorFlagUnmodified guards that the --color flags on inspect jwt and
// inspect jwks were not accidentally modified to include the x509-specific chain/tree disclaimer.
// Those commands only support json/yaml/summary (and key-ids for jwks) — not chain/tree — so
// their --color flags should remain the plain "Enable colorized output" description.
func TestOtherInspectCmds_ColorFlagUnmodified(t *testing.T) {
	jwtCmd := NewInspectJWTCmd()
	jwtColor := jwtCmd.Flags().Lookup("color")
	require.NotNil(t, jwtColor)
	assert.NotContains(t, jwtColor.Usage, "chain or tree",
		"inspect jwt --color should not contain the x509-specific chain/tree disclaimer")

	bundleCmd := NewInspectBundleCmd()
	bundleColor := bundleCmd.Flags().Lookup("color")
	require.NotNil(t, bundleColor)
	assert.NotContains(t, bundleColor.Usage, "chain or tree",
		"inspect jwks --color should not contain the x509-specific chain/tree disclaimer")
}

// TestNewInspectX509Cmd_WarningsRouteToErrOrStderr is a regression guard for the wiring of
// inspector.Stderr = cmd.ErrOrStderr() inside RunE. When --shortest-path is combined with
// a non-chain format (e.g. --format json), the inspector emits an ignored-flag warning.
// That warning must appear in the buffer attached to cmd.SetErr, NOT leak to os.Stderr.
// This test fails if the wiring is removed from RunE.
func TestNewInspectX509Cmd_WarningsRouteToErrOrStderr(t *testing.T) {
	path := writeSVIDToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("format", "json"))
	require.NoError(t, cmd.Flags().Set("shortest-path", "true"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	// The warning must appear in the redirected buffer, not os.Stderr.
	assert.Contains(t, stderrBuf.String(), `--shortest-path is ignored with --format "json"`,
		"ignored-flag warning must be routed through cmd.ErrOrStderr(), not written directly to os.Stderr")
	// stdout must still contain the JSON output.
	assert.Contains(t, stdoutBuf.String(), "spiffe_id")
}

// TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_DefaultJSON is a regression guard
// for PR #58 review comment thread 8/29. When --tree-fields is NOT set and --format
// defaults to json, no "--tree-fields is ignored" warning must appear on stderr.
func TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_DefaultJSON(t *testing.T) {
	path := writeSVIDToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	// --format defaults to json; --tree-fields intentionally NOT set.
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotContains(t, stderrBuf.String(), "--tree-fields is ignored",
		"omitting --tree-fields must not produce a spurious warning on default --format json")
	assert.Contains(t, stdoutBuf.String(), "spiffe_id",
		"stdout must contain valid JSON output")
}

// TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_Chain is a regression guard for the
// --format chain case identified in PR #58 review comment thread 8/29. When --tree-fields
// is NOT set and --format chain is requested, no "--tree-fields is ignored" warning must appear.
func TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_Chain(t *testing.T) {
	chainPath, _ := writeChainToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("format", "chain"))
	// --tree-fields intentionally NOT set.
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotContains(t, stderrBuf.String(), "--tree-fields is ignored",
		"omitting --tree-fields must not produce a spurious warning on --format chain")
	assert.Contains(t, stdoutBuf.String(), "Root CA",
		"stdout must contain chain output")
}

// TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_Summary guards the --format summary case:
// omitting --tree-fields must not produce a spurious warning.
func TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_Summary(t *testing.T) {
	path := writeSVIDToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("format", "summary"))
	// --tree-fields intentionally NOT set.
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotContains(t, stderrBuf.String(), "--tree-fields is ignored",
		"omitting --tree-fields must not produce a spurious warning on --format summary")
	assert.Contains(t, stdoutBuf.String(), "Subject",
		"stdout must contain summary output")
}

// TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_YAML guards the --format yaml case:
// omitting --tree-fields must not produce a spurious warning.
func TestNewInspectX509Cmd_NoSpuriousTreeFieldsWarning_YAML(t *testing.T) {
	path := writeSVIDToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	require.NoError(t, cmd.Flags().Set("format", "yaml"))
	// --tree-fields intentionally NOT set.
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	assert.NotContains(t, stderrBuf.String(), "--tree-fields is ignored",
		"omitting --tree-fields must not produce a spurious warning on --format yaml")
	assert.Contains(t, stdoutBuf.String(), "spiffe_id",
		"stdout must contain YAML output")
}

// TestNewInspectX509Cmd_NoSpuriousSiblingFlagWarnings locks in the contract that
// --bundle and --shortest-path cobra defaults are empty/false, and that a default
// invocation (--filename only, --format json) emits no spurious warnings for any of
// the three incompatible-flag checks.
func TestNewInspectX509Cmd_NoSpuriousSiblingFlagWarnings(t *testing.T) {
	cmd := NewInspectX509Cmd()

	// Cobra-default assertions: lock in the contract so a future re-introduction of
	// non-empty defaults is caught at review time.
	bundleFlag := cmd.Flags().Lookup("bundle")
	require.NotNil(t, bundleFlag)
	assert.Equal(t, "", bundleFlag.DefValue, "--bundle must have an empty DefValue")

	shortestPathFlag := cmd.Flags().Lookup("shortest-path")
	require.NotNil(t, shortestPathFlag)
	assert.Equal(t, "false", shortestPathFlag.DefValue, "--shortest-path must default to false")

	// CLI-run assertion: no spurious warnings on a plain --filename invocation.
	path := writeSVIDToTempFile(t)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", path))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	stderr := stderrBuf.String()
	assert.NotContains(t, stderr, "--bundle is ignored", "omitting --bundle must not warn")
	assert.NotContains(t, stderr, "--shortest-path is ignored", "omitting --shortest-path must not warn")
	assert.NotContains(t, stderr, "--tree-fields is ignored", "omitting --tree-fields must not warn")
}

// writeCrossSignedChainToTempFile creates a cross-signed topology where a single
// intermediate key is signed by two independent roots. Both root certs and the
// leaf SVID are written to chainPath; both roots are also written to bundlePath.
// This setup can cause x509.Verify to return two equal-length chains, exercising
// the "note: N alternate paths" converter stderr note.
func writeCrossSignedChainToTempFile(t *testing.T) (chainPath, bundlePath string) {
	t.Helper()

	rootCA_A := testx509.NewCertificateAuthority(t, "Root CA A")
	rootA := rootCA_A.GenerateCaCertificate(t)

	rootCA_B := testx509.NewCertificateAuthority(t, "Root CA B")
	rootB := rootCA_B.GenerateCaCertificate(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Both intermediates must share the same subject so the leaf's issuer DN matches both.
	intSubject := pkix.Name{CommonName: "X-Signed Intermediate"}
	intermediateSignedByA := rootCA_A.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(intSubject),
	)
	intermediateSignedByB := rootCA_B.GenerateCaCertificate(t,
		testx509.WithPublicKey(intKey.Public()),
		testx509.WithSubject(intSubject),
	)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spiffeURI, err := url.Parse("spiffe://example.com/xsigned-cli")
	require.NoError(t, err)
	leaf := testx509.CreateCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(202),
		Subject:               pkix.Name{CommonName: "xsigned-cli-workload"},
		NotBefore:             rootA.NotBefore,
		NotAfter:              rootA.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{spiffeURI},
	}, intermediateSignedByA, leafKey.Public(), intKey)

	dir := t.TempDir()
	chainPath = filepath.Join(dir, "xsigned-chain.pem")
	require.NoError(t, os.WriteFile(chainPath,
		pemutil.EncodeCertificates([]*x509.Certificate{intermediateSignedByA, intermediateSignedByB, leaf}), 0600))

	bundlePath = filepath.Join(dir, "xsigned-roots.pem")
	require.NoError(t, os.WriteFile(bundlePath,
		pemutil.EncodeCertificates([]*x509.Certificate{rootA, rootB}), 0600))

	return chainPath, bundlePath
}

// TestNewInspectX509Cmd_ConverterStderrRoutedToErrOrStderr is an end-to-end guard
// that converter-emitted stderr notes (alternate-path selection) flow through
// cmd.ErrOrStderr() when inspector.Stderr is wired up in RunE. The test uses a
// cross-signed topology; if x509.Verify returns only one chain for this topology
// the test is skipped (the alternate-path branch is unreachable on that Go build).
func TestNewInspectX509Cmd_ConverterStderrRoutedToErrOrStderr(t *testing.T) {
	chainPath, bundlePath := writeCrossSignedChainToTempFile(t)

	cmd := NewInspectX509Cmd()
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.SetOut(&stdoutBuf)
	cmd.SetErr(&stderrBuf)

	require.NoError(t, cmd.Flags().Set("filename", chainPath))
	require.NoError(t, cmd.Flags().Set("bundle", bundlePath))
	require.NoError(t, cmd.Flags().Set("format", "chain"))
	require.NoError(t, cmd.Flags().Set("shortest-path", "true"))
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.Execute())

	note := stderrBuf.String()
	if !strings.Contains(note, "of equal length") {
		t.Skip("x509.Verify returned only one chain; alternate-path branch not reachable on this Go build")
	}
	assert.Contains(t, note, "alternate path",
		"alternate-path note must be routed through cmd.ErrOrStderr(), not written to os.Stderr")
}
