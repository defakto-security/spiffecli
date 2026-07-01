package bundle

import (
	"fmt"
	"strings"

	"github.com/alecthomas/chroma/quick"
)

type BundleOutputOptions struct {
	Indent     bool
	Color      bool
	KeyIdsOnly bool
	Keys       bool
}

type BundleInspector struct {
	Location      string
	OutputFormat  string
	OutputOptions BundleOutputOptions
}

func (o *BundleOutputOptions) InColor() bool {
	return o.Color
}

func (i *BundleInspector) Inspect() (string, error) {

	if i.Location == "" {
		return "", fmt.Errorf("must specify a file or URL containing the bundle")
	}

	bundle, err := NewJwkSource(i.Location)
	if err != nil {
		return "", err
	}
	keySet, err := bundle.ParseKeys()
	if err != nil {
		return "", err
	}

	if len(keySet.Keys) == 0 {
		return "", fmt.Errorf("no keys found in bundle")
	}

	formatter, exists := FormatMap[i.OutputFormat]
	var inspectionOutput string
	if !exists {
		return "", fmt.Errorf("output format '%s' not supported", i.OutputFormat)
	}

	inspectionOutput, err = formatter.Converter(keySet, i.OutputOptions)
	if err != nil {
		return "", fmt.Errorf("error converting JWKS to %s: %w", formatter.Label, err)
	}
	if i.OutputOptions.Color && i.OutputFormat != "summary" {
		var b strings.Builder
		err := quick.Highlight(&b, inspectionOutput, formatter.Lexer, "terminal256", "doom-one2")
		if err != nil {
			return "", fmt.Errorf("error colorizing JWKS as %s: %w", formatter.Label, err)
		}
		inspectionOutput = b.String()
	}

	return inspectionOutput, nil
}
