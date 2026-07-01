package stringtime

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDuration_JSON(t *testing.T) {
	cases := []struct {
		strDuration  string
		realDuration time.Duration
	}{
		{
			strDuration:  "0s",
			realDuration: time.Duration(0),
		},
		{
			strDuration:  "1s",
			realDuration: time.Second,
		},
		{
			strDuration:  "2m9s",
			realDuration: 2*time.Minute + 9*time.Second,
		},
		{
			strDuration:  "3h12m6s",
			realDuration: 3*time.Hour + 12*time.Minute + 6*time.Second,
		},
	}
	for _, tc := range cases {
		jsonDuration, err := json.Marshal(tc.strDuration)
		require.NoError(t, err)

		t.Run(fmt.Sprintf("Marshal %s", tc.realDuration), func(t *testing.T) {
			d := Duration(tc.realDuration)
			got, err := json.Marshal(d)
			require.NoError(t, err)
			assert.Equal(t, jsonDuration, got)
		})

		t.Run(fmt.Sprintf("Unmarshal %s", tc.strDuration), func(t *testing.T) {
			var d Duration
			err = json.Unmarshal(jsonDuration, &d)
			require.NoError(t, err)
			assert.Equal(t, tc.realDuration, time.Duration(d))
		})
	}
}

type tomlDocument struct {
	D Duration `toml:"d"`
}

func TestDuration_TOML(t *testing.T) {
	cases := []struct {
		strDuration  string
		realDuration time.Duration
	}{
		{
			strDuration:  "0s",
			realDuration: time.Duration(0),
		},
		{
			strDuration:  "1s",
			realDuration: time.Second,
		},
		{
			strDuration:  "2m9s",
			realDuration: 2*time.Minute + 9*time.Second,
		},
		{
			strDuration:  "3h12m6s",
			realDuration: 3*time.Hour + 12*time.Minute + 6*time.Second,
		},
	}
	for _, tc := range cases {
		t.Run(tc.realDuration.String(), func(t *testing.T) {
			in := tomlDocument{
				D: Duration(tc.realDuration),
			}
			got, err := toml.Marshal(in)
			require.NoError(t, err)
			assert.Contains(t, string(got), tc.strDuration)

			var out tomlDocument
			require.NoError(t, toml.Unmarshal(got, &out))
			assert.Equal(t, tc.realDuration, time.Duration(out.D))
		})
	}
}
