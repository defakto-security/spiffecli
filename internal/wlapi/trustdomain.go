package wlapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/jwtauthority"
	"github.com/defakto-security/spiffecli/internal/x509authority"
	"golang.org/x/sync/errgroup"
)

var jwtKeyCounter atomic.Int32

type TrustDomain struct {
	config TrustDomainConfig

	mu              sync.RWMutex
	x509Authorities []x509AuthorityInfo
	jwtAuthorities  []jwtAuthorityInfo
}

type jwtAuthorityInfo struct {
	keyID     string
	pk        crypto.Signer
	expiresAt time.Time
	issuer    string
}

type x509AuthorityInfo struct {
	pk   crypto.Signer
	cert *x509.Certificate
}

func NewTrustDomain(config TrustDomainConfig) (*TrustDomain, error) {
	return &TrustDomain{
		config: config,
	}, nil
}

func (td *TrustDomain) Name() string {
	return td.config.Name.String()
}

func (td *TrustDomain) Bundle() (*spiffebundle.Bundle, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	bundle := spiffebundle.New(td.config.Name)
	for _, x509 := range td.x509Authorities {
		bundle.AddX509Authority(x509.cert)
	}
	for _, jwt := range td.jwtAuthorities {
		if err := bundle.AddJWTAuthority(jwt.keyID, jwt.pk.Public()); err != nil {
			return nil, err
		}
	}
	return bundle, nil
}

func (td *TrustDomain) Run(ctx context.Context) (err error) {
	if err := td.rotateX509Authority(); err != nil {
		return err
	}
	if err := td.rotateJWTAuthority(); err != nil {
		return err
	}

	var workloads []*Workload
	for _, workloadConfig := range td.config.Workloads {
		workload, err := NewWorkload(td, td, workloadConfig)
		if err != nil {
			return err
		}
		log.Printf(
			"Workload: id=%q trustDomain=%q socket=%q",
			workload.config.ID,
			td.config.Name,
			workload.config.SocketPath,
		)
		workloads = append(workloads, workload)
	}

	group, ctx := errgroup.WithContext(ctx)
	for _, workload := range workloads {
		workload := workload
		group.Go(func() error {
			return workload.Run(ctx)
		})
	}
	return group.Wait()
}

func (td *TrustDomain) rotateX509Authority() error {
	log.Printf("Rotating X.509 authority for trust domain %q", td.config.Name)
	x509AuthorityKey, err := generateKey()
	if err != nil {
		return err
	}

	now := time.Now()
	notBefore := now.Add(-backdate)
	notAfter := now.Add(td.config.X509AuthorityTTL)

	x509Authority, err := createRootCertificate(x509AuthorityKey, &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{td.config.Name.ID().URL()},
	})
	if err != nil {
		return errors.Wrap(err, "signing X509 authority")
	}

	td.mu.Lock()
	defer td.mu.Unlock()
	td.x509Authorities = append(td.x509Authorities, x509AuthorityInfo{
		pk:   x509AuthorityKey,
		cert: x509Authority,
	})
	return nil
}

func (td *TrustDomain) rotateJWTAuthority() error {
	log.Printf("Rotating JWT authority for trust domain %q", td.config.Name)
	jwtAuthorityKey, err := generateKey()
	if err != nil {
		return err
	}

	td.mu.Lock()
	defer td.mu.Unlock()
	td.jwtAuthorities = append(td.jwtAuthorities, jwtAuthorityInfo{
		keyID:     fmt.Sprintf("spirl-dev-jwt-key-%d", jwtKeyCounter.Add(1)),
		pk:        jwtAuthorityKey,
		expiresAt: time.Now().Add(td.config.JWTAuthorityTTL),
		// TODO: set issuer to the OIDC endpoint
		issuer: "",
	})
	return nil
}

func (td *TrustDomain) MintX509SVID(id spiffeid.ID, publicKey crypto.PublicKey, ttl time.Duration) (*x509.Certificate, []*x509.Certificate, error) {
	td.mu.RLock()
	x509Authorities := td.x509Authorities
	td.mu.RUnlock()
	if len(td.x509Authorities) == 0 {
		// unexpected
		return nil, nil, errors.New("no X509 authority available for signing")
	}

	authorityInfo := x509Authorities[len(x509Authorities)-1]
	x509Authority, err := x509authority.New(authorityInfo.cert, authorityInfo.pk)
	if err != nil {
		return nil, nil, err
	}

	log.Printf("Minting X509-SVID for %s", id)
	x509SVIDCerts, err := x509Authority.MintX509SVID(x509authority.SVIDParams{
		SPIFFEID:  id,
		PublicKey: publicKey,
		TTL:       ttl,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(x509SVIDCerts) == 0 {
		// unexpected
		return nil, nil, errors.New("no X509 SVID certificates returned from mint")
	}
	return x509SVIDCerts[0], []*x509.Certificate{authorityInfo.cert}, nil
}

func DERFromCertificates(certs []*x509.Certificate) (derBytes []byte) {
	for _, cert := range certs {
		derBytes = append(derBytes, cert.Raw...)
	}
	return derBytes
}

func (td *TrustDomain) X509Bundles() (map[string][]byte, error) {
	var certs []*x509.Certificate
	for _, x509 := range td.x509Authorities {
		certs = append(certs, x509.cert)
	}
	return map[string][]byte{
		td.config.Name.IDString(): DERFromCertificates(certs),
	}, nil
}

func (td *TrustDomain) MintJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration) (string, error) {
	td.mu.RLock()
	jwtAuthorities := td.jwtAuthorities
	td.mu.RUnlock()
	if len(td.jwtAuthorities) == 0 {
		// unexpected
		return "", errors.New("no JWT authority available for signing")
	}

	authorityInfo := jwtAuthorities[len(jwtAuthorities)-1]
	expiresAt := time.Now().Add(td.config.JWTAuthorityTTL)
	jwtAuthority, err := jwtauthority.New(authorityInfo.keyID, authorityInfo.pk, authorityInfo.issuer, expiresAt)
	if err != nil {
		return "", err
	}

	log.Printf("Minting JWT-SVID for %s", id)
	return jwtAuthority.MintJWTSVID(jwtauthority.SVIDParams{
		SPIFFEID: id,
		Audience: audience,
		TTL:      ttl,
	})
}

func (td *TrustDomain) JWTBundles() (map[string][]byte, error) {
	jwtAuthorities := make(map[string]crypto.PublicKey)
	for _, jwt := range td.jwtAuthorities {
		jwtAuthorities[jwt.keyID] = jwt.pk.Public()
	}

	bundle := jwtbundle.FromJWTAuthorities(td.config.Name, jwtAuthorities)
	bundleBytes, err := bundle.Marshal()
	if err != nil {
		return nil, err
	}

	return map[string][]byte{
		td.config.Name.IDString(): bundleBytes,
	}, nil
}

func createRootCertificate(key crypto.Signer, tmpl *x509.Certificate) (*x509.Certificate, error) {
	return createCertificate(key.Public(), tmpl, key, tmpl)
}

func createCertificate(publicKey crypto.PublicKey, tmpl *x509.Certificate, parentKey crypto.Signer, parent *x509.Certificate) (*x509.Certificate, error) {
	sn, err := newSerialNumber()
	if err != nil {
		return nil, errors.Wrap(err, "generating serial number")
	}
	tmpl.SerialNumber = sn
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, publicKey, parentKey)
	if err != nil {
		return nil, errors.Wrap(err, "creating certificate")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		// unexpected
		return nil, errors.Wrap(err, "parsing created certificate")
	}
	return cert, nil
}
