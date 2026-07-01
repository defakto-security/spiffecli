package wlapi

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pkg/errors"
	"github.com/sourcegraph/conc"
	"golang.org/x/sync/errgroup"
)

const (
	sockFileName = "wlapi.sock"
	svidFileName = "x509svid.pem"
	tdExt        = ".x509bundle.pem"
	backdate     = time.Second
)

func Run(ctx context.Context, config Config) error {
	var tds []*TrustDomain
	for _, tdConfig := range config.TrustDomains {
		td, err := NewTrustDomain(tdConfig)
		if err != nil {
			return errors.Wrap(err, "initializing trust domain")
		}
		log.Printf(
			"Trust domain: name=%q X509AuthorityTTL=%q JWTAuthorityTTL=%q",
			tdConfig.Name,
			tdConfig.X509AuthorityTTL,
			tdConfig.JWTAuthorityTTL,
		)
		tds = append(tds, td)
	}

	var wg conc.WaitGroup
	defer wg.Wait()

	group, ctx := errgroup.WithContext(ctx)
	for _, td := range tds {
		td := td
		group.Go(func() error {
			return td.Run(ctx)
		})
	}

	if config.Federation.Port > 0 {
		group.Go(func() error {
			return runFederation(ctx, fmt.Sprintf("localhost:%d", config.Federation.Port), tds)
		})
	}

	return group.Wait()
}
