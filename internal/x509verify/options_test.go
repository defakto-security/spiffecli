package x509verify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/defakto-security/spiffecli/internal/pemutil"
	"github.com/defakto-security/spiffecli/internal/test/testx509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOptions(t *testing.T) {
	tests := []struct {
		name    string
		v       Verifier
		wantErr string
	}{
		{
			name:    "missing certificate",
			v:       Verifier{},
			wantErr: "must specify a file",
		},
		{
			name: "invalid format",
			v:    Verifier{Certificate: "cert.pem", Format: "base64"},
			wantErr: "invalid --format",
		},
		{
			name: "valid pem format",
			v:    Verifier{Certificate: "cert.pem", Format: "pem"},
		},
		{
			name: "valid der format",
			v:    Verifier{Certificate: "cert.pem", Format: "der"},
		},
		{
			name:    "invalid ca-format",
			v:       Verifier{Certificate: "cert.pem", CaBundle: "bundle.pem", CaFormat: "invalid"},
			wantErr: "invalid --ca-format",
		},
		{
			name: "valid jks ca-format",
			v:    Verifier{Certificate: "cert.pem", CaBundle: "bundle.jks", CaFormat: "jks"},
		},
		{
			name: "valid p12 ca-format",
			v:    Verifier{Certificate: "cert.pem", CaBundle: "bundle.p12", CaFormat: "p12"},
		},
		{
			name:    "invalid root-program",
			v:       Verifier{Certificate: "cert.pem", RootProgram: "notmozilla"},
			wantErr: "invalid --root-program",
		},
		{
			name: "valid mozilla root-program",
			v:    Verifier{Certificate: "cert.pem", RootProgram: "mozilla"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.v.validateOptions()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyCertificate_ShowPath(t *testing.T) {
	root, bundleFile := setupRootAndBundle(t)

	intCa := testx509.NewCertificateAuthority(t, "Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	client := Verifier{
		Certificate: chainFile,
		CaBundle:    bundleFile,
		CaFormat:    "pem",
		ShowPath:    true,
	}

	path, err := client.VerifyCertificate()
	require.NoError(t, err)
	assert.Contains(t, path, "validation path")
}

func TestVerifyCertificate_SystemBundle(t *testing.T) {
	// Create a cert signed by a well-known system CA - instead just test
	// that the system bundle path is reached (will fail verification but cover code)
	root, _ := setupRootAndBundle(t)

	intCa := testx509.NewCertificateAuthority(t, "Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	client := Verifier{
		Certificate:  chainFile,
		SystemBundle: true,
	}

	// This will fail verification (cert not from system CA) but should reach the system bundle path
	_, err := client.VerifyCertificate()
	assert.Error(t, err) // cert not trusted by system
}

func TestVerifyCertificate_InvalidCertPath(t *testing.T) {
	client := Verifier{
		Certificate: "/nonexistent/cert.pem",
		CaBundle:    "bundle.pem",
		CaFormat:    "pem",
	}

	_, err := client.VerifyCertificate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate to validate")
}

func TestVerifyCertificate_InvalidCaBundle(t *testing.T) {
	root, _ := setupRootAndBundle(t)

	intCa := testx509.NewCertificateAuthority(t, "Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	chainFile := writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})

	client := Verifier{
		Certificate: chainFile,
		CaBundle:    "/nonexistent/bundle.pem",
		CaFormat:    "pem",
	}

	_, err := client.VerifyCertificate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA bundle")
}

func writeSignedChainPEM(t *testing.T, root *testx509.CertificateAuthority) string {
	t.Helper()
	intCa := testx509.NewCertificateAuthority(t, "Intermediate CA")
	intCert := root.GenerateCaCertificate(t, testx509.WithPublicKey(intCa.Public()), testx509.WithSubject(intCa.Subject()))
	leafCert := intCa.GenerateLeafCertificate(t, testx509.WithSubject(pkix.Name{CommonName: "example.com"}))
	return writeChainAsPem(t, []*x509.Certificate{leafCert, intCert})
}

// Test multiple validation paths
func TestVerifyCertificate_MultiplePaths(t *testing.T) {
	root1 := testx509.NewCertificateAuthority(t, "Root CA 1")
	root1Cert := root1.GenerateCaCertificate(t)
	root2 := testx509.NewCertificateAuthority(t, "Root CA 2")
	root2Cert := root2.GenerateCaCertificate(t)

	// Bundle with both roots
	bundleBytes := append(pemutil.EncodeCertificate(root1Cert), pemutil.EncodeCertificate(root2Cert)...)
	bundlePath := writeTempFile(t, "bundle.pem", bundleBytes)

	// Cert chain from root1
	chainFile := writeSignedChainPEM(t, root1)

	client := Verifier{
		Certificate: chainFile,
		CaBundle:    bundlePath,
		CaFormat:    "pem",
		ShowPath:    true,
	}

	path, err := client.VerifyCertificate()
	require.NoError(t, err)
	assert.Contains(t, path, "path")
}
