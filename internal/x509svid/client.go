package x509svid

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	identityexchange "github.com/defakto-security/spiffecli/internal/identity-exchange"
	"github.com/defakto-security/spiffecli/internal/x509util"
	"google.golang.org/grpc"
)

type X509SVIDClient struct {
	Filename          string
	WorkloadAPISocket string
	Format            string
	Password          string
}

func IdentityExchangeInterceptor(jwtToken string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(identityexchange.AppendTokenToOutgoingContext(ctx, jwtToken), desc, cc, method, opts...)
	}
}

func (c *X509SVIDClient) RequestX509SVID(ctx context.Context) error {
	if err := c.validateOptions(); err != nil {
		return fmt.Errorf("invalid option: %v", err)
	}

	exchangeToken := identityexchange.IDExchangeTokenFromContext(ctx)

	var clientOptions workloadapi.SourceOption
	if exchangeToken == "" {
		clientOptions = workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))
	} else {
		clientOptions = workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket), workloadapi.WithDialOptions(grpc.WithStreamInterceptor(IdentityExchangeInterceptor(exchangeToken))))
	}

	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create x509Source: %w", err)
	}
	defer func() { _ = x509Source.Close() }()

	// Fetch x509 SVID
	svid, err := x509Source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("unable to fetch x509 SVID: %w", err)
	}

	if err := c.outputSVID(svid, os.Stdout); err != nil {
		return fmt.Errorf("failed to output x509 SVID: %w", err)
	}

	return nil
}

func (c *X509SVIDClient) Verifyx509SVID(ctx context.Context) error {
	if err := c.validateOptions(); err != nil {
		return fmt.Errorf("invalid option: %v", err)
	}

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))

	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create x509Source: %w", err)
	}
	defer func() { _ = x509Source.Close() }()

	certs, err := c.getCertificateChain()
	if err != nil {
		return fmt.Errorf("failed to get certificate chain: %v", err)
	}

	_, _, err = x509svid.Verify(certs, x509Source)
	if err != nil {
		return fmt.Errorf("failed to verify certificate chain: %w", err)
	}

	return nil
}

func (c *X509SVIDClient) getCertificateChain() ([]*x509.Certificate, error) {
	if c.Filename == "" {
		return nil, fmt.Errorf("must specify a file from which to read the x509 SVID")
	}

	return x509util.ReadCertificatesFromFile(c.Filename, c.Format, c.Password)
}

func (c *X509SVIDClient) validateOptions() error {
	if c.Format != "" {
		switch c.Format {
		case "pem":
		case "der":
		default:
			return fmt.Errorf("unknown format: %s", c.Format)
		}
	}

	return nil
}

func (c *X509SVIDClient) outputSVID(svid *x509svid.SVID, w io.Writer) error {
	var cert, privateKey []byte
	var err error
	switch c.Format {
	case "pem":
		cert, privateKey, err = svid.Marshal()
	case "der":
		cert, privateKey, err = svid.MarshalRaw()
	default:
		cert, privateKey, err = svid.Marshal()
	}

	if err != nil {
		return fmt.Errorf("failed to marshal x509 SVID: %w", err)
	}

	if c.Filename != "" {
		err := os.WriteFile(privateKeyFilename(c.Filename), privateKey, 0600)
		if err != nil {
			return fmt.Errorf("failed to write private key to file: %w", err)
		}

		err = os.WriteFile(c.Filename, cert, 0600)
		if err != nil {
			return fmt.Errorf("failed to write cert to file: %w", err)
		}
	} else {
		_, _ = fmt.Fprintln(w, string(cert))
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, string(privateKey))
	}

	return nil
}

// privateKeyFilename returns the file name with -key appended
// to the end of the name before the file extension. For example,
// cert.pem becomes cert-key.pem
func privateKeyFilename(filename string) string {
	parts := strings.SplitN(filename, ".", 2)
	if len(parts) == 1 {
		return fmt.Sprintf("%s-key", filename)
	}
	return fmt.Sprintf("%s-key.%s", parts[0], parts[1])
}
