package testhttpd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// NewFileServerWithHeader creates a test HTTP server that serves a single file with custom headers.
// It returns the server and a cleanup function that should be deferred.
//
// Example usage:
//
//	headers := map[string]string{"Content-Type": "application/json"}
//	server, cleanup := NewFileServerWithHeader(t, "testdata/example.json", headers)
//	defer cleanup()
func NewFileServerWithHeader(t *testing.T, filename string, headers map[string]string) (*httptest.Server, func()) {
	t.Helper()

	// Ensure the file exists
	fileInfo, err := os.Stat(filename)
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set custom headers
		for key, value := range headers {
			w.Header().Set(key, value)
		}
		http.ServeFile(w, r, filename)
	})

	// Create a test server
	server := httptest.NewServer(handler)

	// Return the server and a cleanup function
	cleanup := func() {
		server.Close()
	}

	t.Logf("Serving %s (%d bytes) at %s", filepath.Base(filename), fileInfo.Size(), server.URL)
	return server, cleanup
}
