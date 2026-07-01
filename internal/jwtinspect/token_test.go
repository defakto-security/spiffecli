package jwtinspect

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"encoding/json"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestToken(t *testing.T, claims jwt.Claims, signingKey jose.SigningKey) *jwt.JSONWebToken {
	signer, err := jose.NewSigner(signingKey,
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	builder := jwt.Signed(signer)
	builder = builder.Claims(claims)
	serialized, err := builder.Serialize()
	require.NoError(t, err)

	// We decode the same way the inspector does
	tok, err := DeserializeJwt(serialized)
	require.NoError(t, err)

	return tok
}

func generateRSAKey(t *testing.T) jose.SigningKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return jose.SigningKey{Algorithm: jose.RS256, Key: key}
}

func readTokenFromFile(t *testing.T, filename string) *jwt.JSONWebToken {
	data, err := os.ReadFile(filename) //nolint:gosec // test file path
	require.NoError(t, err)
	tok, err := DeserializeJwt(string(data))
	require.NoError(t, err)
	return tok
}

func TestConvertTokenToJson(t *testing.T) {
	// Create test cases
	tests := []struct {
		name       string
		claims     jwt.Claims
		options    JwtInspectOutputOptions
		signingKey jose.SigningKey
		validate   func(t *testing.T, result string, err error)
	}{
		{
			name: "basic claims",
			claims: jwt.Claims{
				Subject: "spiffe://example.org/service",
				Issuer:  "test-issuer",
			},
			options:    JwtInspectOutputOptions{Indent: true},
			signingKey: generateRSAKey(t),
			validate: func(t *testing.T, result string, err error) {
				require.NoError(t, err)
				var data map[string]interface{}
				err = json.Unmarshal([]byte(result), &data)
				require.NoError(t, err)
				claims := data["claims"].(map[string]interface{})
				assert.Equal(t, "spiffe://example.org/service", claims["sub"])
				assert.Equal(t, "test-issuer", claims["iss"])
			},
		},
		{
			name: "with headers",
			claims: jwt.Claims{
				Subject: "spiffe://example.org/service",
			},
			options:    JwtInspectOutputOptions{Header: true, Indent: true},
			signingKey: generateRSAKey(t),
			validate: func(t *testing.T, result string, err error) {
				require.NoError(t, err)
				var data map[string]interface{}
				err = json.Unmarshal([]byte(result), &data)
				require.NoError(t, err)
				assert.Contains(t, result, "headers")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := createTestToken(t, tt.claims, tt.signingKey)
			result, err := ConvertTokenToJson(tok, tt.options)
			tt.validate(t, result, err)
		})
	}
}

func TestHappyCases(t *testing.T) {

	// Used to make the summary tests deterministic
	summaryTime := time.Date(2024, 10, 28, 17, 39, 33, 0, time.UTC)

	happyCaseJwtFiles := []string{
		"simple.jwt",
		"badexp.jwt",
		"oauth-with-scopes.jwt",
		"userauth.jwt",
		"svid.jwt",
	}

	// Happy cases
	for _, jwtfile := range happyCaseJwtFiles {
		t.Run(jwtfile, func(t *testing.T) {
			filename := "testdata/" + jwtfile
			tok := readTokenFromFile(t, filename)

			// Test JSON without headers
			actualNoHeader, err := ConvertTokenToJson(tok, JwtInspectOutputOptions{})
			require.NoError(t, err)
			expectedNoHeader, err := os.ReadFile(fmt.Sprintf("%s.%s", filename, "json"))
			require.NoError(t, err)
			require.JSONEq(t, string(expectedNoHeader), actualNoHeader)

			// Test JSON with headers
			actualWithHeader, err := ConvertTokenToJson(tok, JwtInspectOutputOptions{Header: true})
			require.NoError(t, err)
			expectedWithHeader, err := os.ReadFile(fmt.Sprintf("%s.%s", filename, "headers.json"))
			require.NoError(t, err)
			require.JSONEq(t, string(expectedWithHeader), actualWithHeader)

			// Test ConvertTokenToYaml
			actualNoHeaderYaml, err := ConvertTokenToYaml(tok, JwtInspectOutputOptions{})
			require.NoError(t, err)
			expectedNoHeaderYaml, err := os.ReadFile(fmt.Sprintf("%s.%s", filename, "yaml"))
			require.NoError(t, err)
			require.YAMLEq(t, string(expectedNoHeaderYaml), actualNoHeaderYaml)

			// Test ConvertTokenToYaml with headers
			actualWithHeaderYaml, err := ConvertTokenToYaml(tok, JwtInspectOutputOptions{Header: true})
			require.NoError(t, err)
			expectedWithHeaderYaml, err := os.ReadFile(fmt.Sprintf("%s.%s", filename, "headers.yaml"))
			require.NoError(t, err)
			require.YAMLEq(t, string(expectedWithHeaderYaml), actualWithHeaderYaml)

			// Test summary. We override the time and zone to make the test deterministic
			actualDefaultTime, err := convertTokenToSummary(tok, JwtInspectOutputOptions{TimeZone: "America/Los_Angeles"}, summaryTime)
			require.NoError(t, err)
			expectedDefaultTime, err := os.ReadFile(fmt.Sprintf("%s.%s", filename, "summary"))
			require.NoError(t, err)
			assert.Equal(t, string(expectedDefaultTime), actualDefaultTime)

		})
	}

}

func TestEncryptedJwt(t *testing.T) {
	data, err := os.ReadFile("testdata/encrypted.jwt")
	require.NoError(t, err)
	_, err = DeserializeJwt(string(data))
	require.ErrorContains(t, err, "unable to parse JWT")
}

func TestConvertTokenToSummary_InvalidTimezone(t *testing.T) {
	signingKey := generateRSAKey(t)
	tok := createTestToken(t, jwt.Claims{
		Subject: "spiffe://example.org/service",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, signingKey)

	_, err := convertTokenToSummary(tok, JwtInspectOutputOptions{TimeZone: "Not/Real/Zone"}, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error loading timezone")
}

func TestConvertTokenToSummary_PathTraversalTimezone(t *testing.T) {
	signingKey := generateRSAKey(t)
	tok := createTestToken(t, jwt.Claims{
		Subject: "spiffe://example.org/service",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, signingKey)

	tests := []struct {
		name     string
		timezone string
	}{
		{name: "dotdot path", timezone: "../../etc/passwd"},
		{name: "null byte", timezone: "UTC\x00evil"},
		{name: "semicolon", timezone: "UTC;rm -rf /"},
		{name: "dollar sign", timezone: "$(evil)"},
		{name: "pipe", timezone: "UTC|cmd"},
		{name: "backslash", timezone: "America\\Los_Angeles"},
		{name: "space", timezone: "America/New York"},
		{name: "newline", timezone: "UTC\nevil"},
		{name: "colon", timezone: "UTC:8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertTokenToSummary(tok, JwtInspectOutputOptions{TimeZone: tt.timezone}, time.Now())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "error loading timezone")
		})
	}
}

// TestConvertTokenToSummary_LeadingAndConsecutiveSlashTimezone verifies that
// leading-slash and consecutive-slash timezone inputs are rejected end-to-end
// through convertTokenToSummary, mirroring the protection in x509inspect.
func TestConvertTokenToSummary_LeadingAndConsecutiveSlashTimezone(t *testing.T) {
	signingKey := generateRSAKey(t)
	tok := createTestToken(t, jwt.Claims{
		Subject: "spiffe://example.org/service",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, signingKey)

	tests := []struct {
		name     string
		timezone string
	}{
		{name: "leading slash — /etc/localtime", timezone: "/etc/localtime"},
		{name: "leading slash — /proc/self/environ", timezone: "/proc/self/environ"},
		{name: "leading slash — /etc/passwd", timezone: "/etc/passwd"},
		{name: "single slash only", timezone: "/"},
		{name: "double slash only", timezone: "//"},
		{name: "double slash — leading", timezone: "//etc/shadow"},
		{name: "consecutive slashes — mid", timezone: "America//Los_Angeles"},
		{name: "consecutive slashes — trailing", timezone: "America//"},
		{name: "triple consecutive slashes", timezone: "America///Los_Angeles"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := convertTokenToSummary(tok, JwtInspectOutputOptions{TimeZone: tt.timezone}, time.Now())
			require.Error(t, err, "expected rejection of timezone %q", tt.timezone)
			assert.Contains(t, err.Error(), "error loading timezone")
		})
	}
}

func TestConvertTokenToSummary_EmptyTimezoneUsesLocal(t *testing.T) {
	signingKey := generateRSAKey(t)
	tok := createTestToken(t, jwt.Claims{
		Subject: "spiffe://example.org/service",
		Expiry:  jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}, signingKey)

	// Empty timezone must not trigger an error — the caller falls back to time.Local.
	result, err := convertTokenToSummary(tok, JwtInspectOutputOptions{TimeZone: ""}, time.Now())
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}
