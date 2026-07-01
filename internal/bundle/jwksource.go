package bundle

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// A JwkSource is a JWK read from either a file or a URL
type JwkSource struct {
	filename string
	httpUrl  *url.URL
}

// Returns a new JwkSource given either a URL or a file path. We first test if
// it's a URL, and ensure it starts with http(s). This function will normalize
// and validate the path, but not test for existence or network reachability.
func NewJwkSource(path string) (*JwkSource, error) {
	u, err := url.Parse(path)
	if err == nil && u.Scheme != "" && u.Scheme != "file" {
		if strings.HasPrefix(u.Scheme, "http") {
			return &JwkSource{httpUrl: u}, nil
		} else {
			return nil, fmt.Errorf("scheme '%s' not supported. URL: %s", u.Scheme, path)
		}
	} else {
		var cleanPath string
		if err == nil && u.Scheme == "file" {
			cleanPath = filepath.Clean(u.Path)
		} else {
			cleanPath = filepath.Clean(path)
		}
		if cleanPath == "" || cleanPath == "." || cleanPath == ".." {
			return nil, fmt.Errorf("invalid path: '%s', cleaned is '%s", path, cleanPath)
		}
		return &JwkSource{
			filename: cleanPath,
		}, nil
	}
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust domain.
// It implements the Source interface. Since we're reading from a JWK, the
// trust domain is ignored.
func (jwk *JwkSource) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	var jwtb *jwtbundle.Bundle
	var err error
	if jwk.httpUrl != nil {
		// open the URL and grab the JWK
		resp, err := http.Get(jwk.httpUrl.String())
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
		}
		jwtb, err = jwtbundle.Read(trustDomain, resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read JWK from %s: %w", jwk.httpUrl.String(), err)
		}
	} else {
		jwtb, err = jwtbundle.Load(trustDomain, jwk.filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read JWK from %s: %w", jwk.filename, err)
		}
	}
	return jwtb.GetJWTBundleForTrustDomain(trustDomain)

}

func parseJWKS(data []byte) (*jose.JSONWebKeySet, error) {
	jwks := &jose.JSONWebKeySet{}
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}
	return jwks, nil
}

func (jwk *JwkSource) ParseKeys() (*jose.JSONWebKeySet, error) {

	var data []byte
	var err error
	if jwk.httpUrl != nil {
		resp, err := http.Get(jwk.httpUrl.String())
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected HTTP status code: %d", resp.StatusCode)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
	} else {
		data, err = os.ReadFile(jwk.filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
	}
	return parseJWKS(data)

}
