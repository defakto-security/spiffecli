package bundle

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadJWKSFixture(t *testing.T, path string) *jose.JSONWebKeySet {
	t.Helper()
	src, err := NewJwkSource(path)
	require.NoError(t, err)
	jwks, err := src.ParseKeys()
	require.NoError(t, err)
	return jwks
}

func TestFormatMap_ContainsExpectedFormats(t *testing.T) {
	expected := map[string]struct {
		label string
		lexer string
	}{
		"json":    {label: "JSON", lexer: "json"},
		"yaml":    {label: "YAML", lexer: "yaml"},
		"summary": {label: "Summary", lexer: "text"},
		"key-ids": {label: "Key IDs", lexer: "text"},
	}

	assert.Len(t, FormatMap, len(expected), "FormatMap should have exactly %d entries", len(expected))

	for format, want := range expected {
		t.Run(format, func(t *testing.T) {
			f, ok := FormatMap[format]
			require.True(t, ok, "FormatMap should contain %q", format)
			assert.Equal(t, want.label, f.Label)
			assert.Equal(t, want.lexer, f.Lexer)
			require.NotNil(t, f.Converter, "Converter must not be nil for format %q", format)
		})
	}
}

func TestFormatMap_ConverterProducesOutput(t *testing.T) {
	jwks := loadJWKSFixture(t, "testdata/single.jwks")

	for format := range FormatMap {
		t.Run(format, func(t *testing.T) {
			f := FormatMap[format]
			out, err := f.Converter(jwks, BundleOutputOptions{})
			require.NoError(t, err)
			assert.NotEmpty(t, out)
		})
	}
}

func TestFormatMap_UnknownFormatMissing(t *testing.T) {
	_, ok := FormatMap["xml"]
	assert.False(t, ok, "FormatMap should not contain unsupported format 'xml'")
}
