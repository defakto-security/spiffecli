//go:build !windows

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testdataPath returns an absolute path to a testdata file relative to the e2e package dir.
func testdataPath(t *testing.T, rel string) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Join(wd, "..", "..", rel)
}

func TestE2E_InspectJWT(t *testing.T) {
	binary := buildBinary(t)
	jwtFile := testdataPath(t, "jwtinspect/testdata/simple.jwt")

	cmd := exec.Command(binary, "inspect", "jwt", //nolint:gosec // intentional subprocess in test
		"--filename", jwtFile,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "inspect jwt failed: %s", out)

	assert.Contains(t, string(out), "sub")
}

func TestE2E_InspectJWT_Headers(t *testing.T) {
	binary := buildBinary(t)
	jwtFile := testdataPath(t, "jwtinspect/testdata/simple.jwt")

	cmd := exec.Command(binary, "inspect", "jwt", //nolint:gosec // intentional subprocess in test
		"--filename", jwtFile,
		"--headers",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "inspect jwt --headers failed: %s", out)

	assert.Contains(t, string(out), "Algorithm")
}

func TestE2E_InspectJWT_YAML(t *testing.T) {
	binary := buildBinary(t)
	jwtFile := testdataPath(t, "jwtinspect/testdata/simple.jwt")

	cmd := exec.Command(binary, "inspect", "jwt", //nolint:gosec // intentional subprocess in test
		"--filename", jwtFile,
		"--format", "yaml",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "inspect jwt --format yaml failed: %s", out)

	assert.Contains(t, string(out), "sub:")
}

func TestE2E_InspectJWKS(t *testing.T) {
	binary := buildBinary(t)
	jwksFile := testdataPath(t, "bundle/testdata/single.jwks")

	cmd := exec.Command(binary, "inspect", "jwks", //nolint:gosec // intentional subprocess in test
		"--location", jwksFile,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "inspect jwks failed: %s", out)

	assert.Contains(t, string(out), "kty")
}

func TestE2E_InspectJWT_NoFile(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "inspect", "jwt") //nolint:gosec // intentional subprocess in test
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "must specify a file")
}

func TestE2E_InspectJWKS_NoLocation(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "inspect", "jwks") //nolint:gosec // intentional subprocess in test
	out, err := cmd.CombinedOutput()
	require.Error(t, err)
	assert.NotEmpty(t, out)
}