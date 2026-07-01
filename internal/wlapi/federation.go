package wlapi

import (
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
)

func runFederation(ctx context.Context, endpoint string, tds []*TrustDomain) error {
	if err := http.ListenAndServe(endpoint, federationHandler(tds)); err != nil { //nolint:gosec // dev server, no timeout needed
		return errors.Wrap(err, "serving federation")
	}
	return nil
}

type federationHandler []*TrustDomain

func (tds federationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dir, name := path.Split(r.URL.Path)
	if r.Method != http.MethodGet || dir != "/" || name == "" {
		http.Error(w, "only GET /<trustdomain> is supported", http.StatusBadRequest)
		return
	}

	for _, td := range tds {
		if td.Name() == name {
			bundle, err := td.Bundle()
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to get bundle: %v", err), http.StatusInternalServerError)
				return
			}
			renderBundle(w, bundle)
			return
		}
	}
	http.Error(w, fmt.Sprintf("no such trust domain %q", name), http.StatusNotFound)
}

func renderBundle(w http.ResponseWriter, bundle *spiffebundle.Bundle) {
	data, err := bundle.Marshal()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to render bundle: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
