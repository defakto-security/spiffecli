package wlapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	workloadapi "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	gojwtsvid "github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	goworkloadapi "github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func testConfig(t *testing.T) (Config, string) {
	t.Helper()

	// Use os.MkdirTemp to get a short path; t.TempDir() includes the full test
	// name and can exceed the 104-byte macOS UNIX socket path limit.
	tmpDir, err := os.MkdirTemp("", "wlapitest")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	socketPath := filepath.Join(tmpDir, "workload.sock")

	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	id, err := spiffeid.FromString("spiffe://example.com/test")
	require.NoError(t, err)

	cfg := Config{
		TrustDomains: []TrustDomainConfig{
			{
				Name:             td,
				X509AuthorityTTL: 24 * time.Hour,
				JWTAuthorityTTL:  24 * time.Hour,
				Workloads: []WorkloadConfig{
					{
						ID:               id,
						SocketPath:       socketPath,
						X509SVIDTTL:      time.Hour,
						X509SVIDRotateAt: time.Hour,
						JWTSVIDTTL:       time.Hour,
					},
				},
			},
		},
	}
	return cfg, socketPath
}

func startTestServer(t *testing.T) string {
	t.Helper()

	cfg, socketPath := testConfig(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		_ = Run(ctx, cfg)
	}()

	waitForUnixSocket(t, socketPath)
	return socketPath
}

func waitForUnixSocket(t *testing.T, socketPath string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for workload socket %s", socketPath)
}

func TestRun_StartsWorkloadAPI(t *testing.T) {
	socketPath := startTestServer(t)

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	client := workloadapi.NewSpiffeWorkloadAPIClient(conn)
	require.NotNil(t, client)
}

func TestRun_FetchX509SVID(t *testing.T) {
	socketPath := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := goworkloadapi.WithClientOptions(goworkloadapi.WithAddr("unix://" + socketPath))
	x509Source, err := goworkloadapi.NewX509Source(ctx, clientOpts)
	require.NoError(t, err)
	defer func() { _ = x509Source.Close() }()

	svid, err := x509Source.GetX509SVID()
	require.NoError(t, err)
	require.NotNil(t, svid)
	assert.Equal(t, "spiffe://example.com/test", svid.ID.String())
}

func TestRun_FetchJWTSVID(t *testing.T) {
	socketPath := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := goworkloadapi.WithClientOptions(goworkloadapi.WithAddr("unix://" + socketPath))
	jwtSource, err := goworkloadapi.NewJWTSource(ctx, clientOpts)
	require.NoError(t, err)
	defer func() { _ = jwtSource.Close() }()

	svid, err := jwtSource.FetchJWTSVID(ctx, gojwtsvid.Params{Audience: "test-audience"})
	require.NoError(t, err)
	require.NotNil(t, svid)
	assert.Equal(t, "spiffe://example.com/test", svid.ID.String())
	assert.Contains(t, svid.Audience, "test-audience")
}

func TestRun_FetchX509Bundles(t *testing.T) {
	socketPath := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := goworkloadapi.WithClientOptions(goworkloadapi.WithAddr("unix://" + socketPath))
	x509Source, err := goworkloadapi.NewX509Source(ctx, clientOpts)
	require.NoError(t, err)
	defer func() { _ = x509Source.Close() }()

	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	bundle, err := x509Source.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.True(t, len(bundle.X509Authorities()) > 0)
}

func TestRun_FetchJWTBundles(t *testing.T) {
	socketPath := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOpts := goworkloadapi.WithClientOptions(goworkloadapi.WithAddr("unix://" + socketPath))
	jwtSource, err := goworkloadapi.NewJWTSource(ctx, clientOpts)
	require.NoError(t, err)
	defer func() { _ = jwtSource.Close() }()

	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)

	bundle, err := jwtSource.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.True(t, len(bundle.JWTAuthorities()) > 0)
}

func TestNewWorkload_CreatesSocketDir(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "subdir", "workload.sock")

	td, err := spiffeid.TrustDomainFromString("example.com")
	require.NoError(t, err)
	id, err := spiffeid.FromString("spiffe://example.com/test")
	require.NoError(t, err)

	tdConfig := TrustDomainConfig{
		Name:             td,
		X509AuthorityTTL: 24 * time.Hour,
		JWTAuthorityTTL:  24 * time.Hour,
	}
	trustDomain, err := NewTrustDomain(tdConfig)
	require.NoError(t, err)
	require.NoError(t, trustDomain.rotateX509Authority())
	require.NoError(t, trustDomain.rotateJWTAuthority())

	config := WorkloadConfig{
		ID:               id,
		SocketPath:       socketPath,
		X509SVIDTTL:      time.Hour,
		X509SVIDRotateAt: time.Hour,
		JWTSVIDTTL:       time.Hour,
	}

	workload, err := NewWorkload(trustDomain, trustDomain, config)
	require.NoError(t, err)
	require.NotNil(t, workload)
}
