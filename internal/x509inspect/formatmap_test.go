package x509inspect

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatMap_ContainsExpectedFormats(t *testing.T) {
	expected := map[string]struct {
		label string
		lexer string
	}{
		"json":    {label: "JSON", lexer: "json"},
		"yaml":    {label: "YAML", lexer: "yaml"},
		"summary": {label: "Summary", lexer: "text"},
		"chain":   {label: "Chain", lexer: "text"},
		"tree":    {label: "Tree", lexer: "text"},
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
	_, leaf, _ := newCAAndLeafSVID(t, "spiffe://example.com/test")

	for format := range FormatMap {
		t.Run(format, func(t *testing.T) {
			f := FormatMap[format]
			out, err := f.Converter([]*x509.Certificate{leaf}, X509ConvertOptions{})
			require.NoError(t, err)
			assert.NotEmpty(t, out)
		})
	}
}

func TestFormatMap_UnknownFormatMissing(t *testing.T) {
	_, ok := FormatMap["xml"]
	assert.False(t, ok, "FormatMap should not contain unsupported format 'xml'")
}
