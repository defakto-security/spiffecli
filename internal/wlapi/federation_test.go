package wlapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTrustDomain(t *testing.T, name string) *TrustDomain {
	t.Helper()

	td, err := spiffeid.TrustDomainFromString(name)
	require.NoError(t, err)

	trustDomain, err := NewTrustDomain(TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, trustDomain.rotateX509Authority())
	require.NoError(t, trustDomain.rotateJWTAuthority())
	return trustDomain
}

func TestFederationHandler_GetBundle(t *testing.T) {
	td := newTestTrustDomain(t, "example.com")
	handler := federationHandler([]*TrustDomain{td})

	req := httptest.NewRequest(http.MethodGet, "/example.com", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Contains(t, body, "keys")
	keys := body["keys"].([]any)
	assert.NotEmpty(t, keys)
}

func TestFederationHandler_NotFound(t *testing.T) {
	td := newTestTrustDomain(t, "example.com")
	handler := federationHandler([]*TrustDomain{td})

	req := httptest.NewRequest(http.MethodGet, "/other.com", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestFederationHandler_InvalidMethod(t *testing.T) {
	td := newTestTrustDomain(t, "example.com")
	handler := federationHandler([]*TrustDomain{td})

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"POST method", http.MethodPost, "/example.com"},
		{"root path", http.MethodGet, "/"},
		{"empty name", http.MethodGet, "//"},
		{"nested path", http.MethodGet, "/a/b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestRenderBundle(t *testing.T) {
	td := newTestTrustDomain(t, "example.com")
	bundle, err := td.Bundle()
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	renderBundle(rec, bundle)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.NotEmpty(t, rec.Body.Bytes())
}
