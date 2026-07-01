package jwtinspect

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlags(t *testing.T) {
	inspector := JwtInspector{}
	output, err := inspector.Inspect()
	require.ErrorContains(t, err, "must specify a file containing the JWT")
	require.Equal(t, output, "")

	inspector = JwtInspector{Filename: "testdata/nonexistent.jwt"}
	output, err = inspector.Inspect()
	require.ErrorContains(t, err, "failed to read JWT from file 'testdata/nonexistent.jwt'")
	require.Equal(t, output, "")

	inspector = JwtInspector{Filename: "testdata/simple.jwt", OutputFormat: "unsupported"}
	output, err = inspector.Inspect()
	require.ErrorContains(t, err, "output format 'unsupported' not supported")
	require.Equal(t, output, "")

	inspector = JwtInspector{Filename: "testdata/simple.jwt", OutputFormat: "json", OutputOptions: JwtInspectOutputOptions{Color: true}}
	_, err = inspector.Inspect()
	require.NoError(t, err)

}

func TestInspectSvid(t *testing.T) {
	inspector := JwtInspector{Filename: "testdata/svid.jwt", IsSvid: true}
	output, err := inspector.Inspect()
	require.NoError(t, err)
	require.Equal(t, output, "")

	inspector = JwtInspector{Filename: "testdata/svid.jwt", OutputFormat: "json"}
	output, err = inspector.Inspect()
	require.NoError(t, err)
	expected, err := os.ReadFile("testdata/svid.jwt.json")
	require.NoError(t, err)
	require.JSONEq(t, output, string(expected))

	inspector = JwtInspector{Filename: "testdata/encrypted.jwt", IsSvid: true}
	output, err = inspector.Inspect()
	require.ErrorContains(t, err, "unable to deserialize JWT token")
	require.Equal(t, output, "")

	inspector = JwtInspector{Filename: "testdata/simple.jwt", IsSvid: true}
	output, err = inspector.Inspect()
	require.ErrorContains(t, err, "token is not an SPIFFE SVID")
	require.Equal(t, output, "")

}

func TestInspectEncrypted(t *testing.T) {
	inspector := JwtInspector{Filename: "testdata/encrypted.jwt"}
	output, err := inspector.Inspect()
	require.ErrorContains(t, err, "unable to deserialize JWT token")
	require.Equal(t, output, "")
}

func TestInspect_Summary_ValidTimezone(t *testing.T) {
	inspector := JwtInspector{
		Filename:      "testdata/simple.jwt",
		OutputFormat:  "summary",
		OutputOptions: JwtInspectOutputOptions{TimeZone: "UTC"},
	}
	output, err := inspector.Inspect()
	require.NoError(t, err)
	assert.NotEmpty(t, output)
}

func TestInspect_Summary_InvalidTimezone(t *testing.T) {
	inspector := JwtInspector{
		Filename:      "testdata/simple.jwt",
		OutputFormat:  "summary",
		OutputOptions: JwtInspectOutputOptions{TimeZone: "../../etc/passwd"},
	}
	_, err := inspector.Inspect()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error loading timezone")
}
