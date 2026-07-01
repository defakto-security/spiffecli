package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/cloudflare/cfssl/helpers"
)

type RemoteBundle struct {
	Url    string
	Base64 bool
	Format string
	Parser func(*http.Response) (io.Reader, error)
}

// Microsoft has a *.cab file in a well-known location, but it only contains a
// list of thumbprints that doesn't entirely overlap with Mozilla's list.
// Chrome's list can be retrieved with a bit of HTML-stripping and parsing of a
// couple of files in chromium's source, but that is brittle. Apple provides an
// unhelpful list of CAs in a webpage. For now, we'll just support Mozilla.
// robstradling has already solved all of this. We can periodically
// reconstruct trust stores by using the public postgres db from crt.sh.
var RootPrograms = map[string]RemoteBundle{
	"mozilla": {Url: "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites", Format: "pem", Parser: parseMozilla},
}

// Reads a certificate chain from a file
func ReadCertificatesFromFile(filename string, format string, password string) ([]*x509.Certificate, error) {
	fileBytes, err := os.ReadFile(filename) //nolint:gosec // user-provided file path
	if err != nil {
		return nil, fmt.Errorf("failed to read cert from file: %w", err)
	}
	switch format {
	case "der":
		var certs []*x509.Certificate

		// First we try using the cfssl helper. This works fine for non-PKS#12 DER files
		// Note that we don't want any private key that might be in the file
		certs, _, err := helpers.ParseCertificatesDER(fileBytes, password)
		if err != nil {
			// If that fails, we try using the pkcs12 library in order to get the chain
			_, cert, caCerts, err := pkcs12.DecodeChain(fileBytes, password)
			if err != nil {
				return nil, fmt.Errorf("failed to parse as DER: %w", err)
			}
			certs = append([]*x509.Certificate{cert}, caCerts...)
			return certs, nil
		}
		return certs, nil
	default: // pem and default
		certs, err := helpers.ParseCertificatesPEM(fileBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse as PEM: %w", err)
		}

		return certs, nil
	}
}

type HTTPClient interface {
	GetPeerCertificates(url *url.URL) ([]*x509.Certificate, error)
}

type RealHTTPClient struct {
	Client *http.Client
}

func (c *RealHTTPClient) GetPeerCertificates(url *url.URL) ([]*x509.Certificate, error) {
	resp, err := c.Client.Get(url.String())
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", url.String(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check if we have a valid TLS connection state
	if resp.TLS == nil {
		return nil, fmt.Errorf("invalid TLS connection state")
	}
	return resp.TLS.PeerCertificates, nil
}

// Pulls the certificate chain from an HTTPs endpoint
func ReadCertificatesFromEndpoint(client HTTPClient, url *url.URL) ([]*x509.Certificate, error) {
	return client.GetPeerCertificates(url)
}

// Given a certificate chain, separate into the leaf and the intermediates
func ExtractLeafAndIntermediates(certs []*x509.Certificate) (*x509.Certificate, *x509.CertPool, error) {
	switch len(certs) {
	case 0:
		return nil, nil, fmt.Errorf("empty certificate chain")
	case 1:
		return certs[0], nil, nil
	default:
		var leaf *x509.Certificate
		intermediates := x509.NewCertPool()
		for _, cert := range certs {
			if leaf == nil && !cert.IsCA {
				leaf = cert
			} else {
				intermediates.AddCert(cert)
			}
		}
		if leaf == nil {
			return nil, nil, fmt.Errorf("no leaf certificate found in chain")
		}
		return leaf, intermediates, nil
	}
}

// The main difference with ReadCertificatesFromFile is that this returns a
// CertPool, which gets passed into the verification function. It also handles
// Java KeyStores and PKCS#12 files.
func ParseCaBundleFromFile(filePath string, password string, format string) (*x509.CertPool, error) {

	switch format {
	case "pem":
		return helpers.LoadPEMCertPool(filePath)
	case "jks", "p12":
		data, err := os.ReadFile(filePath) //nolint:gosec // user-provided file path
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
		return LoadPKCS12CertPool(data, password)
	default:
		return nil, fmt.Errorf("unsupported file format: %s", format)
	}
}

// Downloads a remote bundle to a temporary file and then calls ParseCaBundleFromFile
func ParseRemoteBundle(remoteBundle RemoteBundle) (*x509.CertPool, error) {
	// download to temporary file first
	tempFile, err := os.CreateTemp("", "root-program-download-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
	}()

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(remoteBundle.Url) //nolint:gosec // URL comes from a trusted internal config
	if err != nil {
		return nil, fmt.Errorf("failed to send GET request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	// Call the program-specific parser to get a reader
	reader, err := remoteBundle.Parser(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	_, err = io.Copy(tempFile, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to copy bundle to temporary file: %w", err)
	}

	return ParseCaBundleFromFile(tempFile.Name(), "", remoteBundle.Format)
}

func LoadPKCS12CertPool(p12data []byte, password string) (*x509.CertPool, error) {
	certs, err := pkcs12.DecodeTrustStore(p12data, password)
	if err != nil {
		return nil, fmt.Errorf("could not convert PKCS#12 to PEM: %w", err)
	}

	certPool := x509.NewCertPool()

	for _, cert := range certs {
		certPool.AddCert(cert)
	}
	return certPool, nil

}

func IsPem(data []byte) bool {
	// Check if it's a PEM file (PKCS#12 is not PEM encoded)
	block, _ := pem.Decode(data)
	return block != nil
}

// Mozilla's URL goes straight to a PEM file. Chrome-parsing was a bit more
// involved, but I've removed that for now
func parseMozilla(resp *http.Response) (io.Reader, error) {
	return resp.Body, nil
}
