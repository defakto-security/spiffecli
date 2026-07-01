package x509authority

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/clock"
	"github.com/defakto-security/spiffecli/internal/x509svid"
	"github.com/defakto-security/spiffecli/internal/x509util"
)

const (
	// SVIDBackdatePeriod is how long to backdate SVIDs to account for clock
	// skew.
	SVIDBackdatePeriod = time.Second * 10
)

var (
	ErrInvalidParam = errors.New("invalid parameter")
)

type SVIDParams struct {
	SPIFFEID  spiffeid.ID
	PublicKey crypto.PublicKey
	TTL       time.Duration
}

type Option func(*Authority)

func WithClock(clk clock.Clock) Option {
	return func(a *Authority) {
		a.clk = clk
	}
}

type Authority struct {
	cert *x509.Certificate
	key  crypto.Signer
	clk  clock.Clock
}

func New(cert *x509.Certificate, key crypto.Signer, opts ...Option) (*Authority, error) {
	switch {
	case cert == nil:
		return nil, errors.New("cert is required")
	case key == nil:
		return nil, errors.New("key is required")
	}
	a := &Authority{
		cert: cert,
		key:  key,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

func (a *Authority) MintX509SVID(params SVIDParams) ([]*x509.Certificate, error) {
	switch {
	case params.SPIFFEID.IsZero():
		return nil, errors.Wrap(ErrInvalidParam, "SPIFFEID unset")
	case params.PublicKey == nil:
		return nil, errors.Wrap(ErrInvalidParam, "PublicKey unset")
	case params.TTL <= 0:
		return nil, errors.Wrap(ErrInvalidParam, "TTL unset or negative")
	}

	now := a.clk.Now()

	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, err
	}

	notBefore, notAfter, err := determineLifetime(now, params.TTL, a.cert.NotAfter)
	if err != nil {
		return nil, err
	}

	subjectKeyID, err := x509util.GetSubjectKeyID(params.PublicKey)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		URIs:         []*url.URL{params.SPIFFEID.URL()},
		// TODO: Reevaluate the subject properties
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRL"},
			ExtraNames:   []pkix.AttributeTypeAndValue{x509svid.UniqueIDAttribute(params.SPIFFEID)},
		},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		SubjectKeyId:   subjectKeyID,
		AuthorityKeyId: a.cert.SubjectKeyId,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}

	cert, err := createCertificate(template, a.cert, params.PublicKey, a.key)
	if err != nil {
		return nil, errors.Wrap(err, "creating X509-SVID")
	}

	return []*x509.Certificate{cert}, nil
}

func createCertificate(template, parent *x509.Certificate, pub, priv interface{}) (*x509.Certificate, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDER)
}

func determineLifetime(now time.Time, ttl time.Duration, expirationCap time.Time) (notBefore, notAfter time.Time, err error) {
	if !now.Before(expirationCap) {
		return time.Time{}, time.Time{}, errors.New("authority is expired")
	}
	notBefore = now.Add(-SVIDBackdatePeriod)
	notAfter = now.Add(ttl)
	if notAfter.After(expirationCap) {
		notAfter = expirationCap
	}
	return notBefore, notAfter, nil
}
