package jwtsvid

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/defakto-security/spiffecli/internal/bundle"
	identityexchange "github.com/defakto-security/spiffecli/internal/identity-exchange"
	"google.golang.org/grpc"
)

type JWTSVIDClient struct {
	Decode            bool
	Filename          string
	Audiences         []string
	Token             string
	WorkloadAPISocket string
	BundleSource      string
	TrustDomain       string
}

func IdentityExchangeInterceptor(jwtToken string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(identityexchange.AppendTokenToOutgoingContext(ctx, jwtToken), method, req, reply, cc, opts...)
	}
}

func (c *JWTSVIDClient) RequestJWTSVID(ctx context.Context) error {
	if err := c.validateOptions(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	exchangeToken := identityexchange.IDExchangeTokenFromContext(ctx)

	// Create client options to setup expected socket path
	var clientOptions workloadapi.SourceOption
	if exchangeToken == "" {
		clientOptions = workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))
	} else {
		clientOptions = workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket), workloadapi.WithDialOptions(grpc.WithUnaryInterceptor(IdentityExchangeInterceptor(exchangeToken))))
	}

	// Create a JWTSource to fetch SVIDs
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("unable to create JWTSource: %w", err)
	}
	defer func() { _ = jwtSource.Close() }()

	// Fetch JWT SVID
	svid, err := jwtSource.FetchJWTSVID(ctx, c.createParams())
	if err != nil {
		return fmt.Errorf("unable to fetch JWT SVID: %w", err)
	}

	if err := c.outputSVID(svid, os.Stdout); err != nil {
		return fmt.Errorf("failed to output JWT SVID: %w", err)
	}

	return nil
}

func (c *JWTSVIDClient) VerifyJWTSVID(ctx context.Context) error {
	if err := c.validateOptions(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	jwtSource, err := c.getBundleSource(ctx)
	if err != nil {
		return fmt.Errorf("could not retrieve JWT bundle: %w", err)
	}
	if closer, ok := jwtSource.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	token, err := c.getToken()

	if err != nil {
		return fmt.Errorf("could not get token: %w", err)
	}
	_, err = jwtsvid.ParseAndValidate(token, jwtSource, c.Audiences)
	if err != nil {
		return fmt.Errorf("unable to validate JWT SVID token: %v", err)
	}

	return nil
}

func (c *JWTSVIDClient) getBundleSource(ctx context.Context) (jwtbundle.Source, error) {
	if c.BundleSource != "" {
		return bundle.NewJwkSource(c.BundleSource)
	} else {
		clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(c.WorkloadAPISocket))

		// Create a JWTSource to validate provided tokens from clients
		jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("unable to create JWTSource: %w", err)
		}
		return jwtSource, nil
	}
}

func (c *JWTSVIDClient) getToken() (string, error) {
	if c.Token != "" {
		return c.Token, nil
	}

	if c.Filename != "" {
		file, err := os.Open(c.Filename)
		if err != nil {
			return "", fmt.Errorf("failed to open token file %s: %w", c.Filename, err)
		}

		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			return scanner.Text(), nil
		}

		if scanner.Err() == nil {
			return "", fmt.Errorf("the token file is empty")
		}

		return "", fmt.Errorf("failed to read a line from token file: %w", scanner.Err())
	}

	return "", fmt.Errorf("no token provided. Use the -token or -filename flags")
}

func (c *JWTSVIDClient) validateOptions() error {
	if len(c.Audiences) == 0 {
		return fmt.Errorf("must specify a list of audiences with the flag --audiences")
	}

	if c.BundleSource != "" && c.TrustDomain == "" {
		return fmt.Errorf("trust domain must be specified when using the --bundle flag")
	}

	return nil
}

func (c *JWTSVIDClient) outputSVID(svid *jwtsvid.SVID, w io.Writer) error {
	switch {
	case c.Decode:
		marshalled, err := json.Marshal(svid)
		if err != nil {
			return fmt.Errorf("unable to decode jwt-svid: %w", err)
		}

		_, _ = fmt.Fprintln(w, string(marshalled))
	case c.Filename != "":
		err := os.WriteFile(c.Filename, []byte(svid.Marshal()), 0600)
		if err != nil {
			return fmt.Errorf("failed to write JWT SVID to file: %w", err)
		}
	default:
		_, _ = fmt.Fprintln(w, svid.Marshal())
	}

	return nil
}

func (c *JWTSVIDClient) createParams() jwtsvid.Params {
	params := jwtsvid.Params{
		Audience: c.Audiences[0],
	}
	if len(c.Audiences) > 1 {
		params.ExtraAudiences = c.Audiences[1:]
	}
	return params
}
