package testauthority

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/defakto-security/spiffecli/internal/jwtsvid"
	"github.com/defakto-security/spiffecli/internal/test/testkey"
)

const (
	DefaultX509SVIDTTL = 24 * time.Hour
	DefaultJWTSVIDTTL  = 24 * time.Hour
)

type AuthorityOption = func(*Authority) error

func WithClock(clk clock.Clock) AuthorityOption {
	return func(a *Authority) error {
		a.clk = clk
		return nil
	}
}

type X509SVIDOption func(c *x509SVIDConfig)

func WithX509SVIDTTL(ttl time.Duration) X509SVIDOption {
	return func(c *x509SVIDConfig) {
		c.ttl = ttl
	}
}

func WithPublicKey(publicKey crypto.PublicKey) X509SVIDOption {
	return func(c *x509SVIDConfig) {
		c.publicKey = publicKey
	}
}

type JWTSVIDOption func(c *jwtSVIDConfig)

func WithJWTSVIDTTL(ttl time.Duration) JWTSVIDOption {
	return func(c *jwtSVIDConfig) {
		c.ttl = ttl
	}
}

type x509SVIDConfig struct {
	publicKey crypto.PublicKey
	ttl       time.Duration
}

type jwtSVIDConfig struct {
	ttl time.Duration
}

type Authority struct {
	keys testkey.Keys
	clk  clock.Clock

	td spiffeid.TrustDomain

	// x509Authorities is the list of X.509 authorities. The first is the
	// "active" authority and corresponds to the private key stored in
	// x509CAKey.
	x509Authorities []*x509.Certificate
	x509CAKey       crypto.Signer

	// jwtAuthorities is the list of JWT authorities. The key identified by
	// jwtKeyID is the "active" authority and corresponds to the private key
	// stored in jwtKey.
	jwtAuthorities map[string]crypto.PublicKey
	jwtKeyID       string
	jwtKey         crypto.Signer

	// tracks the bundle sequence number
	sequenceNumber uint64
}

func New(trustDomainName string, opts ...AuthorityOption) *Authority {
	a := &Authority{
		td: spiffeid.RequireTrustDomainFromString(trustDomainName),
	}

	for _, opt := range opts {
		check(opt(a))
	}

	return a
}

func (a *Authority) TrustDomain() spiffeid.TrustDomain {
	return a.td
}

func (a *Authority) MintX509SVID(path string, opts ...X509SVIDOption) *x509svid.SVID {
	id, err := spiffeid.FromPath(a.td, path)
	check(err)

	var c x509SVIDConfig
	for _, opt := range opts {
		opt(&c)
	}

	var key crypto.Signer
	if c.publicKey == nil {
		key = a.keys.EC256()
		c.publicKey = key.Public()
	}
	if c.ttl == 0 {
		c.ttl = DefaultX509SVIDTTL
	}

	svid := a.createX509SVID(id, c.publicKey, c.ttl)

	return &x509svid.SVID{
		ID:           id,
		Certificates: append([]*x509.Certificate{svid}, a.x509Authorities[0]),
		PrivateKey:   key,
	}
}

func (a *Authority) MintJWTSVID(path string, audience []string, opts ...JWTSVIDOption) string {
	id, err := spiffeid.FromPath(a.td, path)
	check(err)

	var c jwtSVIDConfig
	for _, opt := range opts {
		opt(&c)
	}

	return a.createJWTSVID(id, audience, c.ttl)
}

func (a *Authority) Bundle() *spiffebundle.Bundle {
	bundle := spiffebundle.New(a.td)
	bundle.SetX509Authorities(a.X509Bundle().X509Authorities())
	bundle.SetJWTAuthorities(a.JWTBundle().JWTAuthorities())
	bundle.SetSequenceNumber(a.sequenceNumber)
	return bundle
}

func (a *Authority) X509Authority() (*x509.Certificate, crypto.Signer) {
	a.prepareX509CA()
	return a.x509Authorities[0], a.x509CAKey
}

func (a *Authority) X509Bundle() *x509bundle.Bundle {
	a.prepareX509CA()
	return x509bundle.FromX509Authorities(a.td, a.x509Authorities[len(a.x509Authorities)-1:])
}

func (a *Authority) JWTAuthority() (string, crypto.Signer) {
	a.prepareJWTKey()
	return a.jwtKeyID, a.jwtKey
}

func (a *Authority) JWTBundle() *jwtbundle.Bundle {
	a.prepareJWTKey()
	return jwtbundle.FromJWTAuthorities(a.td, a.jwtAuthorities)
}

func (a *Authority) Rotate() *spiffebundle.Bundle {
	a.RotateX509Authority()
	a.RotateJWTAuthority()
	return a.Bundle()
}

func (a *Authority) RotateX509Authority() {
	a.x509CAKey = nil
	a.prepareX509CA()
}

func (a *Authority) RotateJWTAuthority() {
	a.jwtKey = nil
	a.prepareJWTKey()
}

func (a *Authority) prepareX509CA() {
	if a.x509CAKey != nil {
		return
	}
	a.x509CAKey = a.keys.EC256()
	x509CA := a.createCACertificate(a.x509CAKey, nil, nil)
	a.x509Authorities = append([]*x509.Certificate{x509CA}, a.x509Authorities...)
	a.sequenceNumber++
}

func (a *Authority) prepareJWTKey() {
	if a.jwtKey != nil {
		return
	}
	a.jwtKey = a.keys.EC256()
	a.jwtKeyID = newJWTKeyID()
	if a.jwtAuthorities == nil {
		a.jwtAuthorities = make(map[string]crypto.PublicKey)
	}
	a.jwtAuthorities[a.jwtKeyID] = a.jwtKey.Public()
	a.sequenceNumber++
}

func (a *Authority) createCACertificate(caKey crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	serial := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: fmt.Sprintf("CA %x", serial)},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent = tmpl
		parentKey = caKey
	}
	return a.createCertificate(tmpl, caKey.Public(), parent, parentKey, time.Hour*24*30)
}

func (a *Authority) createX509SVID(id spiffeid.ID, publicKey crypto.PublicKey, ttl time.Duration) *x509.Certificate {
	a.prepareX509CA()

	serial := newSerial()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{id.URL()},
	}
	return a.createCertificate(tmpl, publicKey, a.x509Authorities[0], a.x509CAKey, ttl)
}

func (a *Authority) createCertificate(tmpl *x509.Certificate, publicKey crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer, ttl time.Duration) *x509.Certificate {
	now := a.clk.Now()

	tmpl.NotBefore = now
	tmpl.NotAfter = now.Add(ttl)

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, publicKey, parentKey)
	check(err)
	cert, err := x509.ParseCertificate(certDER)
	check(err)
	return cert
}

func newSerial() *big.Int {
	serial := make([]byte, 8)
	_, err := rand.Read(serial)
	check(err)
	return new(big.Int).SetBytes(serial)
}

func (a *Authority) createJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration) string {
	a.prepareJWTKey()

	if ttl == 0 {
		ttl = DefaultJWTSVIDTTL
	}

	signer := jwtsvid.NewSigner(jwtsvid.SignerConfig{
		Clock: a.clk,
	})

	token, err := signer.SignToken(id, audience, a.clk.Now().Add(ttl), a.jwtKey, a.jwtKeyID)
	check(err)

	return token
}

func newJWTKeyID() string {
	choices := make([]byte, 32)
	_, err := rand.Read(choices)
	check(err)
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := new(bytes.Buffer)
	for _, choice := range choices {
		_ = buf.WriteByte(alphabet[int(choice)%len(alphabet)])
	}
	return buf.String()
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
