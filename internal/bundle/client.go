package bundle

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type BundleClient struct {
	WorkloadAPISocket string
	Filename          string
	TrustDomain       string
}

type Bundle interface {
	Marshal() ([]byte, error)
}

func (c *BundleClient) verifyOptions() error {
	if c.TrustDomain == "" {
		return fmt.Errorf("must set the --trust-domain flag")
	}

	return nil
}

func (c *BundleClient) GetX509Bundle(ctx context.Context) error {
	if err := c.verifyOptions(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// Create client options to setup expected socket path
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))

	x509Source, err := workloadapi.NewX509Source(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create x509Source: %w", err)
	}
	defer func() { _ = x509Source.Close() }()

	td, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return fmt.Errorf("failed to parse trust domain: %w", err)
	}

	bundle, err := x509Source.GetX509BundleForTrustDomain(td)
	if err != nil {
		return fmt.Errorf("failed to get x509 bundle: %w", err)
	}

	if err := c.outputBundle(bundle, os.Stdout); err != nil {
		return fmt.Errorf("failed to output bundle: %w", err)
	}

	return nil
}

func (c *BundleClient) GetJWTBundle(ctx context.Context) error {
	if err := c.verifyOptions(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// Create client options to setup expected socket path
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))

	// Create a JWTSource to fetch SVIDs
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create JWTSource: %w", err)
	}
	defer func() { _ = jwtSource.Close() }()

	td, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return fmt.Errorf("failed to parse trust domain: %w", err)
	}

	bundle, err := jwtSource.GetJWTBundleForTrustDomain(td)
	if err != nil {
		return fmt.Errorf("failed to get JWT bundle: %w", err)
	}

	if err := c.outputBundle(bundle, os.Stdout); err != nil {
		return fmt.Errorf("failed to output bundle: %w", err)
	}

	return nil
}

func (c *BundleClient) outputBundle(bundle Bundle, w io.Writer) error {
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	if c.Filename == "" {
		_, _ = fmt.Fprintln(w, string(bundleBytes))
	} else {
		err := os.WriteFile(c.Filename, bundleBytes, 0600)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
	}

	return nil
}
