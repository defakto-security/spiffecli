package jwtsvid

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/stretchr/testify/require"
)

// an example token
var token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTUzMTk1MDAsIm5iZiI6MTY5NTMxOTUwMCwiZXhwIjoxNzk1MzE5NDk5LCJhdWQiOiJBVURJRU5DRSIsImlzcyI6IndsYXBpIiwic3ViIjoic3BpZmZlOi8vYWJjLzEyMyIsImp0aSI6InNwaWZmZTovL2RlZi80NTYifQ.gex5jyTGPsKMCPProPeojvZl70b5dW_SP9QVX1iDOQ86C-kT1aAadk545Id2fKcqxHpa6ZiU324IzqhYOgPdX7yKNPIFCHPDJsh9cgY1mIc_dPz5LyJ_pUkOfhUuCApZ" //nolint:gosec // test JWT token

func TestOutputSVID(t *testing.T) {
	svid, err := jwtsvid.ParseInsecure(token, fakeAudience)
	require.NoError(t, err)

	t.Run("test output jwt token", func(t *testing.T) {
		client := &JWTSVIDClient{}

		var b bytes.Buffer
		err := client.outputSVID(svid, &b)
		require.NoError(t, err)

		require.Equal(t, token, strings.TrimSuffix(b.String(), "\n"))
	})

	t.Run("test output to file", func(t *testing.T) {
		filename := fmt.Sprintf("%s/jwtsvid.jwt", t.TempDir())
		client := &JWTSVIDClient{
			Filename: filename,
		}

		err := client.outputSVID(svid, os.Stdout)
		require.NoError(t, err)

		fileBytes, err := os.ReadFile(filename) //nolint:gosec // test file path
		require.NoError(t, err)

		require.Equal(t, token, strings.TrimSuffix(string(fileBytes), "\n"))
	})

	t.Run("test decode output", func(t *testing.T) {
		client := &JWTSVIDClient{
			Decode: true,
		}

		var b bytes.Buffer
		err := client.outputSVID(svid, &b)
		require.NoError(t, err)

		expectedOutput := `{"ID":"spiffe://abc/123","Audience":["AUDIENCE"],"Expiry":"2026-11-22T03:51:39Z","Claims":{"aud":"AUDIENCE","exp":1795319499,"iat":1695319500,"iss":"wlapi","jti":"spiffe://def/456","nbf":1695319500,"sub":"spiffe://abc/123"},"Hint":""}`
		require.Equal(t, expectedOutput, strings.TrimSuffix(b.String(), "\n"))
	})
}

func TestCreateParams(t *testing.T) {
	client := JWTSVIDClient{Audiences: fakeAudience}
	require.Equal(t, fakeAudience[0], client.createParams().Audience)

	client = JWTSVIDClient{Audiences: fakeAudiences}
	params := client.createParams()
	require.Equal(t, fakeAudiences[0], params.Audience)
	require.Equal(t, fakeAudiences[1:], params.ExtraAudiences)
}

func TestGetToken(t *testing.T) {
	emptyFileName := fmt.Sprintf("%s/empty.jwt", t.TempDir())
	err := os.WriteFile(emptyFileName, []byte{}, 0644) //nolint:gosec // test file
	require.NoError(t, err)

	testcases := []struct {
		description string
		token       string
		filename    string
		expected    string
		err         string
	}{
		{
			description: "token flag",
			token:       token,
			filename:    "abc.123",
			expected:    token,
		},
		{
			description: "token from file",
			filename:    "testdata/token.txt",
			expected:    token,
		},
		{
			description: "file does not exist",
			filename:    "abc.123",
			err:         "failed to open token file abc.123: open abc.123: no such file or directory",
		},
		{
			description: "no token",
			err:         "no token provided. Use the -token or -filename flags",
		},
		{
			description: "empty file",
			filename:    emptyFileName,
			err:         "the token file is empty",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			client := JWTSVIDClient{
				Token:    tc.token,
				Filename: tc.filename,
			}

			token, err := client.getToken()
			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, token)
		})
	}
}
