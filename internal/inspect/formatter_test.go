package inspect

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatter_Fields(t *testing.T) {
	f := Formatter[string, bool]{
		Label:     "JSON",
		Lexer:     "json",
		Converter: func(s string, _ bool) (string, error) { return s, nil },
	}
	assert.Equal(t, "JSON", f.Label)
	assert.Equal(t, "json", f.Lexer)
	require.NotNil(t, f.Converter)
}

func TestFormatter_ZeroValue(t *testing.T) {
	var f Formatter[string, bool]
	assert.Empty(t, f.Label)
	assert.Empty(t, f.Lexer)
	assert.Nil(t, f.Converter)
}

func TestFormatter_ConverterCalledWithArgs(t *testing.T) {
	f := Formatter[string, bool]{
		Label: "flagged",
		Lexer: "text",
		Converter: func(s string, flag bool) (string, error) {
			if flag {
				return s + "-flagged", nil
			}
			return s, nil
		},
	}

	out, err := f.Converter("hello", false)
	require.NoError(t, err)
	assert.Equal(t, "hello", out)

	out, err = f.Converter("hello", true)
	require.NoError(t, err)
	assert.Equal(t, "hello-flagged", out)
}

func TestFormatter_ConverterPropagatesError(t *testing.T) {
	sentinel := errors.New("conversion failed")
	f := Formatter[int, struct{}]{
		Label: "broken",
		Lexer: "text",
		Converter: func(_ int, _ struct{}) (string, error) {
			return "", sentinel
		},
	}

	_, err := f.Converter(42, struct{}{})
	require.ErrorIs(t, err, sentinel)
}

func TestFormatter_WithPointerInputType(t *testing.T) {
	type Input struct{ Value string }
	type Options struct{ Indent bool }

	f := Formatter[*Input, Options]{
		Label: "ptr",
		Lexer: "json",
		Converter: func(in *Input, _ Options) (string, error) {
			if in == nil {
				return "", errors.New("nil input")
			}
			return in.Value, nil
		},
	}

	out, err := f.Converter(&Input{Value: "hello"}, Options{})
	require.NoError(t, err)
	assert.Equal(t, "hello", out)

	_, err = f.Converter(nil, Options{})
	require.Error(t, err)
}

func TestFormatter_WithSliceInputType(t *testing.T) {
	f := Formatter[[]string, struct{}]{
		Label: "join",
		Lexer: "text",
		Converter: func(ss []string, _ struct{}) (string, error) {
			result := ""
			for _, s := range ss {
				result += s
			}
			return result, nil
		},
	}

	out, err := f.Converter([]string{"a", "b", "c"}, struct{}{})
	require.NoError(t, err)
	assert.Equal(t, "abc", out)
}
