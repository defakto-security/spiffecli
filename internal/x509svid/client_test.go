package x509svid

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/stretchr/testify/require"
)

func getFileContent(t testing.TB, filename string) []byte {
	fileBytes, err := os.ReadFile(filename) //nolint:gosec // test file path
	require.NoError(t, err)

	return fileBytes
}

func TestOutputSVID(t *testing.T) {
	// an example cert
	svid, err := x509svid.Load("testdata/cert.pem", "testdata/key.pem")
	require.NoError(t, err)

	cert := getFileContent(t, "testdata/cert.pem")
	privateKey := getFileContent(t, "testdata/key.pem")

	t.Run("test output cert", func(t *testing.T) {
		client := &X509SVIDClient{}

		var b bytes.Buffer
		err := client.outputSVID(svid, &b)
		require.NoError(t, err)

		expectedOutput := fmt.Sprintf("%s\n\n%s\n", cert, privateKey)

		require.Equal(t, expectedOutput, b.String())
	})

	t.Run("test output to file", func(t *testing.T) {
		filename := fmt.Sprintf("%s/cert.pem", t.TempDir())
		client := &X509SVIDClient{
			Filename: filename,
		}

		err := client.outputSVID(svid, os.Stdout)
		require.NoError(t, err)

		certBytes := getFileContent(t, filename)
		require.Equal(t, string(cert), string(certBytes))

		privateKeyBytes := getFileContent(t, privateKeyFilename(filename))
		require.Equal(t, privateKey, privateKeyBytes)
	})

	t.Run("test der type output", func(t *testing.T) {
		filename := fmt.Sprintf("%s/cert.pem", t.TempDir())
		client := &X509SVIDClient{
			Filename: filename,
			Format:   "der",
		}

		err := client.outputSVID(svid, os.Stdout)
		require.NoError(t, err)

		expectedCertBytes, expectedPrivKeyBytes, err := svid.MarshalRaw()
		require.NoError(t, err)

		certBytes := getFileContent(t, filename)
		require.Equal(t, expectedCertBytes, certBytes, "\n")

		privateKeyBytes := getFileContent(t, privateKeyFilename(filename))
		require.Equal(t, expectedPrivKeyBytes, privateKeyBytes)
	})
}

func TestPrivateKeyFilename(t *testing.T) {
	testcases := []struct {
		filename string
		expected string
	}{
		{
			filename: "cert.pem",
			expected: "cert-key.pem",
		},
		{
			filename: "cert.abc.pem",
			expected: "cert-key.abc.pem",
		},
		{
			filename: "cert",
			expected: "cert-key",
		},
	}
	for _, tc := range testcases {
		require.Equal(t, tc.expected, privateKeyFilename(tc.filename))
	}
}

func TestX509SVIDClient_ValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		client  X509SVIDClient
		wantErr string
	}{
		{
			name:   "empty format (default)",
			client: X509SVIDClient{},
		},
		{
			name:   "pem format",
			client: X509SVIDClient{Format: "pem"},
		},
		{
			name:   "der format",
			client: X509SVIDClient{Format: "der"},
		},
		{
			name:    "unknown format",
			client:  X509SVIDClient{Format: "base64"},
			wantErr: "unknown format: base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.client.validateOptions()
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetCert(t *testing.T) {
	pemCert, err := pemutil.ParseCertificates(getFileContent(t, "testdata/cert.pem"))
	require.NoError(t, err)

	derCert, err := x509.ParseCertificates(getFileContent(t, "testdata/cert.der"))
	require.NoError(t, err)

	testcases := []struct {
		desc     string
		filename string
		certs    []*x509.Certificate
		format   string
		err      string
	}{
		{
			desc: "no file",
			err:  "must specify a file from which to read the x509 SVID",
		},
		{
			desc:     "invalid file",
			filename: "abc.123",
			err:      "failed to read cert from file: open abc.123: no such file or directory",
		},
		{
			desc:     "pem cert",
			filename: "testdata/cert.pem",
			format:   "pem",
			certs:    pemCert,
		},
		{
			desc:     "der cert",
			filename: "testdata/cert.der",
			format:   "der",
			certs:    derCert,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			client := &X509SVIDClient{
				Filename: tc.filename,
				Format:   tc.format,
			}

			certs, err := client.getCertificateChain()
			if tc.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.certs, certs)
		})
	}
}
