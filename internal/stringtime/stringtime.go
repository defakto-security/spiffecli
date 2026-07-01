package stringtime

import (
	"time"
)

// Duration is a time.Duration that implements TextMarshaler and TextUnmarshaler.
// Useful for embedding in structs that will be encoded as JSON, TOML, etc.
type Duration time.Duration

func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

func (d *Duration) UnmarshalText(b []byte) error {
	dur, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}
