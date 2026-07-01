package timeutil

import (
	"fmt"
	"regexp"
	"time"
)

var validTimezoneRe = regexp.MustCompile(`^[A-Za-z0-9_+\-]+(/[A-Za-z0-9_+\-]+)*$`)

// LoadTimezone validates name against a segment-based pattern before
// delegating to time.LoadLocation, preventing path-traversal inputs.
func LoadTimezone(name string) (*time.Location, error) {
	if !validTimezoneRe.MatchString(name) {
		return nil, fmt.Errorf("invalid timezone: must be non-empty segments of letters, digits, '_', '+', or '-' separated by '/'")
	}
	return time.LoadLocation(name)
}
