package bundle

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Path validation tests

func TestHappyPaths(t *testing.T) {
	assert := assert.New(t)

	var happyPaths = []struct {
		path string
	}{
		{"bundle.jwk"},
		{"/a/b/c"},
		{"http://example.com/"},
		{"https://example.com/"},
		{"./foo"},
		{"../foo"},
		{"file:///C:/Users/username/Documents/example.txt"},
		{"file:///home/username/documents/example.txt"},
	}

	for _, test := range happyPaths {
		s, err := NewJwkSource(test.path)
		assert.NotNil(s)
		assert.NoError(err)
	}

}

func TestBadPaths(t *testing.T) {
	assert := assert.New(t)
	var badPaths = []struct {
		path string
	}{
		{""},
		{"."},
		{".."},
	}

	for _, test := range badPaths {
		s, err := NewJwkSource(test.path)
		assert.Nil(s)
		assert.Error(err)
	}
}

func TestBadUrls(t *testing.T) {
	assert := assert.New(t)
	var badUrls = []struct {
		url string
	}{
		{"ftp://example.com/this-is-a-bad-path"},
		{"sftp://username@example.com:22/path/to/file"},
		{"mailto:example@email.com"},
		{"tel:+1-555-123-4567"},
		{"jdbc:mysql://localhost:3306/mydatabase"},
		{"market://details?id=com.example.app"},
		{"git://github.com/user/project.git"},
	}

	for _, test := range badUrls {
		s, err := NewJwkSource(test.url)
		assert.Nil(s)
		assert.Error(err)
		assert.ErrorContains(err, test.url)

	}
}

// File-loading tests

var (
	valid_td  = "acme-corp"
	valid_jwk = `{
  "keys": [
    {
      "kty": "EC",
      "kid": "valid-ec-key",
      "crv": "P-256",
      "x": "KTsj64BXFx-1uyoeJBBSp09DR-gDjCJo6Vvzv0isQTY",
      "y": "vp9J7QjbT3NCOS0s8Q9BpMbDlm1P-SDYtqrromNvnds"
    }
  ]
}`

	valid_rsa = `{
	"keys": [
		{
	   		"kty": "RSA",
          	"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          	"e": "AQAB",
          	"alg": "RS256",
          	"kid": "valid-rsa-key"}
       ]
     }`

	invalid_syntax = `{
  "keys": [
    {
      "kty": "RSA",
`
	missing_public_key = `{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "1",
	  "alg": "RS256"
    }
  ]
}`
)

func runJwkFileTest(t *testing.T, jwk string, testFunc func(t *testing.T, tempPath string)) {
	t.Helper()
	tf, err := os.CreateTemp("", "jwksource-test")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tf.Name()) }()

	_, err = tf.Write([]byte(jwk))
	require.NoError(t, err)
	require.NoError(t, tf.Close())

	jwkPath, err := filepath.Abs(tf.Name())
	require.NoError(t, err)
	testFunc(t, jwkPath)
}

func TestValidEcFromFile(t *testing.T) {
	runJwkFileTest(t, valid_jwk, func(t *testing.T, tempPath string) {

		s, err := NewJwkSource(tempPath)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		td, _ := spiffeid.TrustDomainFromString(valid_td)
		bundle, err := s.GetJWTBundleForTrustDomain(td)
		assert.NotNil(t, bundle)
		assert.NoError(t, err)
		assert.False(t, bundle.Empty())
		assert.True(t, bundle.HasJWTAuthority("valid-ec-key"))
	})
}

func TestValidRsaFromFile(t *testing.T) {
	runJwkFileTest(t, valid_rsa, func(t *testing.T, tempPath string) {

		s, err := NewJwkSource(tempPath)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		td, _ := spiffeid.TrustDomainFromString(valid_td)
		bundle, err := s.GetJWTBundleForTrustDomain(td)
		assert.NotNil(t, bundle)
		assert.NoError(t, err)
		assert.False(t, bundle.Empty())
		assert.True(t, bundle.HasJWTAuthority("valid-rsa-key"))
	})
}

func TestMissingPublicKeyFromFile(t *testing.T) {
	runJwkFileTest(t, missing_public_key, func(t *testing.T, tempPath string) {
		s, err := NewJwkSource(tempPath)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		td, _ := spiffeid.TrustDomainFromString(valid_td)
		bundle, err := s.GetJWTBundleForTrustDomain(td)
		assert.Nil(t, bundle)
		assert.ErrorContains(t, err, "invalid RSA key")
	})
}

func TestInvalidJsonFromFile(t *testing.T) {
	runJwkFileTest(t, invalid_syntax, func(t *testing.T, tempPath string) {
		s, err := NewJwkSource(tempPath)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		td, _ := spiffeid.TrustDomainFromString(valid_td)
		bundle, err := s.GetJWTBundleForTrustDomain(td)
		assert.Nil(t, bundle)
		assert.ErrorContains(t, err, "unexpected end of JSON")
	})
}

func TestNonExistentFile(t *testing.T) {
	nonExistentFile := filepath.Join("jwktest", uuid.New().String())
	s, err := NewJwkSource(nonExistentFile)
	assert.NotNil(t, s)
	assert.NoError(t, err)

	td, _ := spiffeid.TrustDomainFromString(valid_td)
	bundle, err := s.GetJWTBundleForTrustDomain(td)
	assert.Nil(t, bundle)
	assert.ErrorContains(t, err, "no such file")
}

// URL-loading tests

func runJwkHttpTest(t *testing.T, jwk string, testFunc func(t *testing.T, tempUrl string)) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jwk))
	}))
	defer server.Close()

	testFunc(t, server.URL)
}

func TestValidEcFromURL(t *testing.T) {
	runJwkHttpTest(t, valid_jwk, func(t *testing.T, tempPath string) {

		s, err := NewJwkSource(tempPath)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		td, _ := spiffeid.TrustDomainFromString(valid_td)
		bundle, err := s.GetJWTBundleForTrustDomain(td)
		assert.NotNil(t, bundle)
		assert.NoError(t, err)
		assert.False(t, bundle.Empty())
		assert.True(t, bundle.HasJWTAuthority("valid-ec-key"))
	})
}
