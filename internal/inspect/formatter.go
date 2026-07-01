package inspect

// Formatter describes how to convert an input value T with options O to a string.
type Formatter[T, O any] struct {
	Label     string
	Lexer     string
	Converter func(T, O) (string, error)
}
