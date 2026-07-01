package timeutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadTimezone_ErrorMessages_ExactText verifies the exact error text produced
// by the regex validation guard so that downstream parsers / scripts
// that grep for specific strings remain stable if the check order or wording
// ever changes.
func TestLoadTimezone_ErrorMessages_ExactText(t *testing.T) {
	want := "invalid timezone: must be non-empty segments of letters, digits, '_', '+', or '-' separated by '/'"

	_, err := LoadTimezone("/etc/passwd")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	_, err = LoadTimezone("America//Los_Angeles")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	_, err = LoadTimezone("America/New York")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())

	_, err = LoadTimezone("America/")
	require.Error(t, err)
	assert.Equal(t, want, err.Error())
}

// TestLoadTimezone_NilLocationOnError asserts that a nil *time.Location is
// always returned alongside every error — callers must check err before
// dereferencing the returned location.
func TestLoadTimezone_NilLocationOnError(t *testing.T) {
	inputs := []string{
		"/etc/passwd",
		"America//Los_Angeles",
		"Bad Name",
		"",
		"../../etc/passwd",
	}
	for _, input := range inputs {
		loc, err := LoadTimezone(input)
		require.Error(t, err, "expected error for %q", input)
		assert.Nil(t, loc, "expected nil location for %q", input)
	}
}

// TestLoadTimezone_NilLocationOnUnknownZone asserts the nil-location contract
// for inputs that pass regex validation but name an unknown timezone.
// time.LoadLocation returns nil on error, so LoadTimezone must propagate that nil.
func TestLoadTimezone_NilLocationOnUnknownZone(t *testing.T) {
	unknownZones := []string{
		"Not/Real/Zone",
		"Fake/City",
		"Invalid/Name/Here",
	}
	for _, name := range unknownZones {
		loc, err := LoadTimezone(name)
		require.Error(t, err, "expected error for unknown zone %q", name)
		assert.Nil(t, loc, "expected nil location for unknown zone %q", name)
	}
}

// TestLoadTimezone_AdditionalInjectionPatterns covers injection variants not
// yet tested: CRLF, horizontal tab, and non-ASCII Unicode — all of which must
// be rejected by the character-allowlist guard.
func TestLoadTimezone_AdditionalInjectionPatterns(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "CRLF injection", input: "UTC\r\nevil"},
		{name: "carriage return only", input: "UTC\revil"},
		{name: "horizontal tab", input: "UTC\tevil"},
		{name: "non-ASCII unicode", input: "Amérique/La_Paz"},
		{name: "backtick", input: "`evil`"},
		{name: "angle bracket open", input: "<script>"},
		{name: "angle bracket close", input: ">redirect"},
		{name: "percent encoding attempt", input: "UTC%2Fevil"},
		{name: "at sign", input: "UTC@8"},
		{name: "hash", input: "UTC#comment"},
		{name: "question mark", input: "UTC?tz=bad"},
		{name: "dot dot no slash", input: "..America"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc, err := LoadTimezone(tt.input)
			require.Error(t, err, "expected rejection of %q", tt.input)
			assert.Contains(t, err.Error(), "invalid timezone")
			assert.Nil(t, loc)
		})
	}
}

func TestLoadTimezone_ReturnedLocation(t *testing.T) {
	loc, err := LoadTimezone("America/Los_Angeles")
	require.NoError(t, err)
	assert.Equal(t, "America/Los_Angeles", loc.String())

	loc, err = LoadTimezone("UTC")
	require.NoError(t, err)
	assert.Equal(t, "UTC", loc.String())
}

// TestLoadTimezone_SegmentRegexBehavior directly tests the structural properties
// of the new segment-based regex, ensuring valid multi-segment paths are accepted
// and degenerate structures (empty segment, slash-only, trailing slash) are rejected.
func TestLoadTimezone_SegmentRegexBehavior(t *testing.T) {
	validCases := []struct {
		name  string
		input string
	}{
		{name: "single segment with digits", input: "UTC"},
		{name: "single segment with plus sign", input: "EST5"},
		{name: "two-segment with plus in second", input: "Etc/GMT+5"},
		{name: "two-segment with minus", input: "Etc/GMT-5"},
		{name: "two-segment with underscores", input: "America/Los_Angeles"},
		{name: "three-segment valid timezone", input: "America/Indiana/Indianapolis"},
	}
	for _, tc := range validCases {
		t.Run("valid/"+tc.name, func(t *testing.T) {
			// regex should pass; LoadLocation may still fail for unknown zones
			ok := validTimezoneRe.MatchString(tc.input)
			assert.True(t, ok, "expected regex to accept %q", tc.input)
		})
	}

	invalidCases := []struct {
		name  string
		input string
	}{
		{name: "empty string", input: ""},
		{name: "single slash", input: "/"},
		{name: "leading slash", input: "/UTC"},
		{name: "trailing slash", input: "UTC/"},
		{name: "consecutive slashes", input: "America//Los_Angeles"},
		{name: "empty middle segment", input: "America//New_York"},
		{name: "slash only between slashes", input: "America///LA"},
	}
	for _, tc := range invalidCases {
		t.Run("invalid/"+tc.name, func(t *testing.T) {
			assert.False(t, validTimezoneRe.MatchString(tc.input), "expected regex to reject %q", tc.input)
		})
	}
}

// TestLoadTimezone_ThreeSegmentValid verifies that 3-segment timezone names accepted
// by the regex are also resolved correctly by time.LoadLocation.
func TestLoadTimezone_ThreeSegmentValid(t *testing.T) {
	loc, err := LoadTimezone("America/Indiana/Indianapolis")
	require.NoError(t, err)
	assert.Equal(t, "America/Indiana/Indianapolis", loc.String())
}

func TestLoadTimezone(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		errContains string
	}{
		{name: "UTC", input: "UTC", wantErr: false},
		{name: "America/Los_Angeles", input: "America/Los_Angeles", wantErr: false},
		{name: "EST", input: "EST", wantErr: false},
		{name: "Etc/GMT+5", input: "Etc/GMT+5", wantErr: false},
		{name: "path traversal dots", input: "../../etc/passwd", wantErr: true, errContains: "invalid timezone"},
		{name: "null byte", input: "UTC\x00evil", wantErr: true, errContains: "invalid timezone"},
		{name: "space", input: "America/New York", wantErr: true, errContains: "invalid timezone"},
		{name: "unknown valid-shaped name", input: "Not/Real/Zone", wantErr: true},
		{name: "empty string", input: "", wantErr: true, errContains: "invalid timezone"},
		{name: "semicolon injection", input: "UTC;rm -rf /", wantErr: true, errContains: "invalid timezone"},
		{name: "dollar sign", input: "$(evil)", wantErr: true, errContains: "invalid timezone"},
		{name: "pipe", input: "UTC|cmd", wantErr: true, errContains: "invalid timezone"},
		{name: "backslash", input: "America\\Los_Angeles", wantErr: true, errContains: "invalid timezone"},
		{name: "colon", input: "UTC:8", wantErr: true, errContains: "invalid timezone"},
		{name: "newline", input: "UTC\nevil", wantErr: true, errContains: "invalid timezone"},
		{name: "dot alone", input: ".", wantErr: true, errContains: "invalid timezone"},
		{name: "Local special name", input: "Local", wantErr: false},
		{name: "leading slash", input: "/etc/localtime", wantErr: true, errContains: "invalid timezone"},
		{name: "absolute path /etc/passwd", input: "/etc/passwd", wantErr: true, errContains: "invalid timezone"},
		{name: "consecutive slashes", input: "America//Los_Angeles", wantErr: true, errContains: "invalid timezone"},
		{name: "trailing slash", input: "America/", wantErr: true, errContains: "invalid timezone"},
		// Additional edge cases for slash validation
		{name: "single slash only", input: "/", wantErr: true, errContains: "invalid timezone"},
		{name: "double slash only", input: "//", wantErr: true, errContains: "invalid timezone"},
		{name: "procfs path", input: "/proc/self/environ", wantErr: true, errContains: "invalid timezone"},
		{name: "leading slash with consecutive", input: "//etc/shadow", wantErr: true, errContains: "invalid timezone"},
		{name: "triple consecutive slashes", input: "America///Los_Angeles", wantErr: true, errContains: "invalid timezone"},
		{name: "consecutive trailing slashes", input: "America//", wantErr: true, errContains: "invalid timezone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc, err := LoadTimezone(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, loc)
			}
		})
	}
}

// TestLoadTimezone_DotSegmentTraversal verifies that dot-segment traversal
// patterns embedded within an otherwise valid-looking path are rejected.
// The segment regex requires each segment to be [A-Za-z0-9_+\-]+, so any
// occurrence of '.' inside a segment causes a mismatch.
func TestLoadTimezone_DotSegmentTraversal(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "dot-dot segment in middle", input: "America/../etc/passwd"},
		{name: "dot segment in middle", input: "America/./Los_Angeles"},
		{name: "double dot alone", input: ".."},
		{name: "dot segment at start with slash", input: "../etc/passwd"},
		{name: "dot in segment", input: "Ameri.ca/LA"},
		{name: "trailing dot in segment", input: "America/LA."},
		{name: "leading dot in segment", input: "America/.hidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loc, err := LoadTimezone(tt.input)
			require.Error(t, err, "expected rejection of %q", tt.input)
			assert.Contains(t, err.Error(), "invalid timezone")
			assert.Nil(t, loc)
		})
	}
}

// TestLoadTimezone_FirstCharConstraint explicitly documents that the segment-based
// regex requires the first character to be in [A-Za-z0-9_+\-], rejecting all
// other leading characters. This was the reviewer's key concern: that the old
// regex allowed leading '/' (e.g. /etc/passwd) which the new one prevents.
func TestLoadTimezone_FirstCharConstraint(t *testing.T) {
	// Characters outside [A-Za-z0-9_+\-] that must be rejected as first char.
	rejectedLeaders := []struct {
		name  string
		input string
	}{
		{name: "exclamation", input: "!UTC"},
		{name: "comma", input: ",UTC"},
		{name: "caret", input: "^UTC"},
		{name: "dot", input: ".UTC"},
		{name: "tilde", input: "~UTC"},
		{name: "asterisk", input: "*UTC"},
		{name: "open paren", input: "(UTC"},
		{name: "close bracket", input: "]UTC"},
	}
	for _, tc := range rejectedLeaders {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			loc, err := LoadTimezone(tc.input)
			require.Error(t, err, "expected rejection of %q", tc.input)
			assert.Contains(t, err.Error(), "invalid timezone")
			assert.Nil(t, loc)
		})
	}

	// Characters in [A-Za-z0-9_+\-] that are valid first chars per the regex.
	// time.LoadLocation may still error for unknown zone names — we only assert
	// that the regex guard itself does not reject them.
	validFirstChars := []struct {
		name  string
		input string
	}{
		{name: "uppercase letter", input: "UTC"},
		{name: "lowercase letter", input: "local"},
		{name: "underscore", input: "_hidden"},
		{name: "plus", input: "+00"},
		{name: "minus", input: "-05"},
	}
	for _, tc := range validFirstChars {
		t.Run("regex_allows/"+tc.name, func(t *testing.T) {
			assert.True(t, validTimezoneRe.MatchString(tc.input),
				"regex should accept %q as syntactically valid", tc.input)
		})
	}
}
