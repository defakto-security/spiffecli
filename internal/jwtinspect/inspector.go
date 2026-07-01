package jwtinspect

import (
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/defakto-security/spiffecli/internal/style"
)

type JwtInspectOutputOptions struct {
	Header   bool
	Indent   bool
	Color    bool
	TimeZone string
}

func (o JwtInspectOutputOptions) InColor() bool {
	return o.Color
}

type JwtInspector struct {
	Filename      string
	IsSvid        bool
	OutputFormat  string
	OutputOptions JwtInspectOutputOptions
}

func (i *JwtInspector) Inspect() (string, error) {

	if i.Filename == "" {
		return "", fmt.Errorf("must specify a file containing the JWT")
	}

	data, err := os.ReadFile(i.Filename)
	if err != nil {
		return "", fmt.Errorf("failed to read JWT from file '%s': %w", i.Filename, err)
	}

	tok, err := DeserializeJwt(string(data))
	if err != nil {
		return "", fmt.Errorf("unable to deserialize JWT token")
	}

	if i.IsSvid {
		// Check if the token is an SPIFFE SVID
		isSvid, _, err := isSvid(tok)
		if err != nil {
			return "", fmt.Errorf("error inspecting JWT: %w", err)
		}

		if !isSvid {
			return "", fmt.Errorf("token is not an SPIFFE SVID")
		}
		return "", nil
	}

	formatter, exists := FormatMap[i.OutputFormat]

	var inspectionOutput string
	if !exists {
		return "", fmt.Errorf("output format '%s' not supported", i.OutputFormat)
	} else {
		converterOutput, err := formatter.Converter(tok, i.OutputOptions)
		if err != nil {
			return "", fmt.Errorf("error converting token to %s: %w", formatter.Label, err)
		}
		if i.OutputOptions.Color && i.OutputFormat != "summary" {
			var b strings.Builder
			err := quick.Highlight(&b, converterOutput, formatter.Lexer, "terminal256", style.TerminalStyle)
			if err != nil {
				return "", fmt.Errorf("error colorizing token as %s: %w", formatter.Label, err)
			}
			inspectionOutput = b.String()
		} else {
			inspectionOutput = converterOutput
		}
	}
	return inspectionOutput, nil
}
