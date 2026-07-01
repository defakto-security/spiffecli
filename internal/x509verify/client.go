package x509verify

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/defakto-security/spiffecli/internal/x509util"
)

type Verifier struct {
	Certificate  string              // URL or file path to certificate chain
	Format       string              // Certificate chain format (pem or der)
	Password     string              // Password, if necessary, for certificate DER file. Note that this will only support a single certificate.
	CaBundle     string              // Path to CA bundle
	CaFormat     string              // CA bundle format (pem, jks, p12)
	CaPassword   string              // Password ("integrity verifier") for CA bundle. A silly thing Java does.
	SystemBundle bool                // Flag to use the system trust store
	RootProgram  string              // Root program to use. Right now only "mozilla" is supported.
	ShowPath     bool                // Show the validation path(s)
	HttpClient   x509util.HTTPClient // Not set by the user, but used for testing
}

func (c *Verifier) VerifyCertificate() (string, error) {
	if err := c.validateOptions(); err != nil {
		return "", fmt.Errorf("invalid option: %v", err)
	}

	if c.HttpClient == nil {
		c.HttpClient = c.createHttpClient()
	}

	leaf, intermediates, err := c.GetCertificateChain()
	if err != nil {
		return "", fmt.Errorf("could not find certificate to validate: %v", err)
	}

	// This is where we need to determine which trust store we're
	// using. It could be:
	// 1. A bundle from a file
	// 2. The system bundle
	// 3. A root program bundle (This requires a download). At the moment only Mozilla
	//    is "easy" to support.
	var roots *x509.CertPool

	switch {
	case c.CaBundle != "":
		// Verify certificate using a trust store on disk.
		roots, err = x509util.ParseCaBundleFromFile(c.CaBundle, c.CaPassword, c.CaFormat)
		if err != nil {
			return "", fmt.Errorf("could not parse CA bundle: %w", err)
		}
	case c.SystemBundle:
		// Verify certificate using the system trust store.
		roots, err = x509.SystemCertPool()
		if err != nil {
			return "", fmt.Errorf("could not get system certificates: %w", err)
		}
	default:
		// Verify certificate using a selected root program bundle.
		roots, err = x509util.ParseRemoteBundle(x509util.RootPrograms[c.RootProgram])
		if err != nil {
			return "", fmt.Errorf("could not retrieve latest root program CA bundle: %w", err)
		}
	}

	// verify cert
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	paths, err := leaf.Verify(opts)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	if c.ShowPath {
		if len(paths) == 1 {
			sb.WriteString("Found single validation path:\n")
		} else {
			fmt.Fprintf(&sb, "Found %d validation paths:\n", len(paths))
		}

		for _, chain := range paths {
			l := list.NewWriter()
			l.SetStyle(list.StyleConnectedLight)
			for _, cert := range chain {
				l.AppendItem(cert.Subject)
				l.Indent()
			}
			sb.WriteString(l.Render())
		}
	}

	return sb.String(), err

}

func (c *Verifier) validateOptions() error {
	if c.Certificate == "" {
		return fmt.Errorf("must specify a file from which to read the x509 certificate")
	}

	if c.Format != "" {
		switch c.Format {
		case "pem":
		case "der":
		default:
			return fmt.Errorf("invalid --format: %s", c.Format)
		}
	}

	if c.CaBundle != "" {
		switch c.CaFormat {
		case "pem":
		case "jks":
		case "p12":
		default:
			return fmt.Errorf("invalid --ca-format: %s", c.CaFormat)
		}
	}

	if c.RootProgram != "" {
		_, validProgram := x509util.RootPrograms[c.RootProgram]
		if !validProgram {
			return fmt.Errorf("invalid --root-program specified: %s", c.RootProgram)
		}
	}

	return nil
}

func (c *Verifier) GetCertificateChain() (*x509.Certificate, *x509.CertPool, error) {

	var certs []*x509.Certificate
	u, err := url.Parse(c.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate URL: %w", err)
	}

	switch u.Scheme {
	case "https":
		certs, err = x509util.ReadCertificatesFromEndpoint(c.HttpClient, u)
	case "file", "":
		var cleanPath string
		if u.Scheme == "file" {
			cleanPath, err = filepath.Abs(u.Path)
		} else {
			cleanPath, err = filepath.Abs(c.Certificate)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get absolute path: %w", err)
		}
		valid, _ := govalidator.IsFilePath(cleanPath)
		if !valid {
			return nil, nil, fmt.Errorf("invalid path: '%s', cleaned is '%s", c.Certificate, cleanPath)
		}
		certs, err = x509util.ReadCertificatesFromFile(c.Certificate, c.Format, c.Password)
	default:
		return nil, nil, fmt.Errorf("scheme '%s' not supported. URL: %s", u.Scheme, c.Certificate)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve certificate(s): %w", err)
	}

	return x509util.ExtractLeafAndIntermediates(certs)

}

func (c *Verifier) createHttpClient() x509util.HTTPClient {
	return &x509util.RealHTTPClient{
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // intentional: user-requested skip verification
				},
			},
		},
	}
}
