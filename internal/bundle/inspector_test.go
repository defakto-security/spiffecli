package bundle

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defakto-security/spiffecli/internal/test/testhttpd"
	"github.com/stretchr/testify/require"
)

func TestBundlePaths(t *testing.T) {
	tests := []struct {
		name        string
		inspector   BundleInspector
		errorString string
	}{
		{
			name:        "Missing bundle path",
			inspector:   BundleInspector{Location: "", OutputFormat: "json"},
			errorString: "must specify a file or URL containing the bundle",
		},
		{
			name:        "Invalid bundle path",
			inspector:   BundleInspector{Location: "testdata/nonexistent.jwks", OutputFormat: "json"},
			errorString: "failed to read file: open testdata/nonexistent.jwks: no such file or directory",
		},
		{
			name:        "Invalid JSON in JWK",
			inspector:   BundleInspector{Location: "testdata/invalid_json.jwks", OutputFormat: "json"},
			errorString: "failed to unmarshal JWKS",
		},
		{
			name:        "No keys in JWK",
			inspector:   BundleInspector{Location: "testdata/invalid.jwks", OutputFormat: "json"},
			errorString: "no keys found in bundle",
		},
		{
			name:        "Valid JWK with single key",
			inspector:   BundleInspector{Location: "testdata/single.jwks", OutputFormat: "json"},
			errorString: "",
		},
		{
			name:        "Valid JWK with multiple keys",
			inspector:   BundleInspector{Location: "testdata/multiple.jwks", OutputFormat: "json"},
			errorString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.inspector.Inspect()
			if tt.errorString != "" {
				require.ErrorContains(t, err, tt.errorString)
			} else {
				require.NoError(t, err)
			}
		})
	}

}

func TestBundleFixtures(t *testing.T) {
	tests := []struct {
		fixture string
	}{
		{
			fixture: "single.jwks",
		},
		{
			fixture: "multiple.jwks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			expected, actual := getExpectedAndActual(t, tt.fixture, "json")
			require.JSONEq(t, expected, actual)
			expected, actual = getExpectedAndActual(t, tt.fixture, "yaml")
			require.YAMLEq(t, expected, actual)
			expected, actual = getExpectedAndActual(t, tt.fixture, "summary")
			require.Equal(t, expected, actual)
			expected, actual = getExpectedAndActual(t, tt.fixture, "key-ids")
			require.Equal(t, expected, actual)
		})
	}
}

func getExpectedAndActual(t *testing.T, fixture string, format string) (string, string) {
	t.Helper()
	fixturePath := filepath.Join("testdata", fixture)
	expected, err := os.ReadFile(fmt.Sprintf("%s.%s", fixturePath, format))
	require.NoError(t, err)

	inspector := BundleInspector{Location: fixturePath, OutputFormat: format}
	actual, err := inspector.Inspect()
	require.NoError(t, err)
	return string(expected), actual
}

func TestBundleUrls(t *testing.T) {

	tests := []struct {
		name        string
		file        string
		wantErr     bool
		errorString string
	}{
		{
			name:        "Invalid JSON in JWK",
			file:        "testdata/invalid_json.jwks",
			wantErr:     true,
			errorString: "failed to unmarshal JWKS",
		},
		{
			name:        "No keys in JWK",
			file:        "testdata/invalid.jwks",
			wantErr:     true,
			errorString: "no keys found in bundle",
		},
		{
			name:        "Valid JWK with single key",
			file:        "testdata/single.jwks",
			wantErr:     false,
			errorString: "",
		},
		{
			name:        "Valid JWK with multiple keys",
			file:        "testdata/multiple.jwks",
			wantErr:     false,
			errorString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := NewJwkServer(t, tt.file)
			inspector := BundleInspector{Location: server.URL, OutputFormat: "json"}
			output, err := inspector.Inspect()
			fmt.Println(output)
			if tt.wantErr {
				require.ErrorContains(t, err, tt.errorString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func NewJwkServer(t *testing.T, filename string) *httptest.Server {
	t.Helper()

	headers := map[string]string{"Content-Type": "application/json"}
	server, cleanup := testhttpd.NewFileServerWithHeader(t, filename, headers)
	t.Cleanup(cleanup)
	return server
}
