package wlapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/sourcegraph/conc"
	workloadapi "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type X509Authority interface {
	MintX509SVID(id spiffeid.ID, publicKey crypto.PublicKey, ttl time.Duration) (*x509.Certificate, []*x509.Certificate, error)
	X509Bundles() (map[string][]byte, error)
}

type JWTAuthority interface {
	MintJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration) (string, error)
	JWTBundles() (map[string][]byte, error)
}

type Workload struct {
	x509Authority X509Authority
	jwtAuthority  JWTAuthority
	config        WorkloadConfig
}

func NewWorkload(x509Authority X509Authority, jwtAuthority JWTAuthority, config WorkloadConfig) (*Workload, error) {
	// Create the socket directory and clean up the existing socket if
	// necessary
	if err := os.MkdirAll(filepath.Dir(config.SocketPath), 0750); err != nil {
		return nil, errors.Wrap(err, "creating socket directory")
	}
	_ = os.Remove(config.SocketPath)

	return &Workload{
		x509Authority: x509Authority,
		jwtAuthority:  jwtAuthority,
		config:        config,
	}, nil
}

func (wl *Workload) Run(ctx context.Context) error {
	listener, err := net.Listen("unix", wl.config.SocketPath)
	if err != nil {
		return errors.Wrap(err, "listening on workload socket")
	}

	server := grpc.NewServer()
	workloadapi.RegisterSpiffeWorkloadAPIServer(server, &handler{
		x509Authority: wl.x509Authority,
		jwtAuthority:  wl.jwtAuthority,
		config:        wl.config,
	})

	var wg conc.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		<-ctx.Done()
		server.GracefulStop()
	})

	return server.Serve(listener)
}

type handler struct {
	workloadapi.UnimplementedSpiffeWorkloadAPIServer

	x509Authority X509Authority
	jwtAuthority  JWTAuthority
	config        WorkloadConfig
}

func (h *handler) FetchX509SVID(_ *workloadapi.X509SVIDRequest, stream workloadapi.SpiffeWorkloadAPI_FetchX509SVIDServer) (err error) {
	defer func() {
		if err != nil {
			log.Printf("FetchX509SVID: %v", err)
		}
	}()

	for {
		x509SVIDKey, err := generateKey()
		if err != nil {
			return status.Errorf(codes.Internal, "generating X509-SVID key: %v", err)
		}

		x509SVIDKeyBytes, err := x509.MarshalPKCS8PrivateKey(x509SVIDKey)
		if err != nil {
			return status.Errorf(codes.Internal, "marshaling X509-SVID key: %v", err)
		}

		x509SVID, x509Authorities, err := h.x509Authority.MintX509SVID(h.config.ID, x509SVIDKey.Public(), h.config.X509SVIDTTL)
		if err != nil {
			return status.Errorf(codes.Internal, "minting X509-SVID: %v", err)
		}

		if err := stream.Send(&workloadapi.X509SVIDResponse{
			Svids: []*workloadapi.X509SVID{
				{
					SpiffeId:    h.config.ID.String(),
					X509Svid:    x509SVID.Raw,
					X509SvidKey: x509SVIDKeyBytes,
					Bundle:      certsBytes(x509Authorities...),
				},
			},
		}); err != nil {
			return err
		}

		select {
		case <-time.After(h.config.X509SVIDRotateAt):
		case <-stream.Context().Done():
			err = stream.Context().Err()
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

func (h *handler) FetchJWTSVID(ctx context.Context, req *workloadapi.JWTSVIDRequest) (*workloadapi.JWTSVIDResponse, error) {
	svid, err := h.jwtAuthority.MintJWTSVID(h.config.ID, req.GetAudience(), h.config.JWTSVIDTTL)
	if err != nil {
		return nil, err
	}
	return &workloadapi.JWTSVIDResponse{
		Svids: []*workloadapi.JWTSVID{
			{
				SpiffeId: h.config.ID.String(),
				Svid:     svid,
			},
		},
	}, nil
}

func (h *handler) FetchX509Bundles(_ *workloadapi.X509BundlesRequest, stream workloadapi.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	bundles, err := h.x509Authority.X509Bundles()
	if err != nil {
		return err
	}
	if err := stream.Send(&workloadapi.X509BundlesResponse{
		Bundles: bundles,
	}); err != nil {
		return err
	}

	// TODO(ENG-701): Send updated bundles over the stream when rotation is implemented.
	<-stream.Context().Done()
	err = stream.Context().Err()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (h *handler) FetchJWTBundles(_ *workloadapi.JWTBundlesRequest, stream workloadapi.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	bundles, err := h.jwtAuthority.JWTBundles()
	if err != nil {
		return err
	}
	if err := stream.Send(&workloadapi.JWTBundlesResponse{
		Bundles: bundles,
	}); err != nil {
		return err
	}

	// TODO(ENG-701): Send updated bundles over the stream when rotation is implemented.
	<-stream.Context().Done()
	err = stream.Context().Err()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
