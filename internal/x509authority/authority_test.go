package x509authority

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/test/testauthority"
	"github.com/defakto-security/spiffecli/internal/test/testclock"
	"github.com/defakto-security/spiffecli/internal/test/testkey"
	"github.com/defakto-security/spiffecli/internal/x509svid"
	"github.com/defakto-security/spiffecli/internal/x509util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	caCert, caKey = testauthority.New("domain.test").X509Authority()
	roots         = x509util.NewCertPool(caCert)
	svidKey       = testkey.EC256()
	workloadID    = spiffeid.RequireFromString("spiffe://domain.test/foo")
)

func TestNew(t *testing.T) {
	_, err := New(nil, caKey)
	require.EqualError(t, err, "cert is required")

	_, err = New(caCert, nil)
	require.EqualError(t, err, "key is required")
}

func TestBadParams(t *testing.T) {
	authority, err := New(caCert, caKey)
	require.NoError(t, err)

	assertBad := func(expectErr string, fn func(*SVIDParams)) {
		t.Helper()
		params := svidParams()
		fn(&params)
		_, err = authority.MintX509SVID(params)
		assert.EqualError(t, err, expectErr+": invalid parameter")
	}

	assertBad("SPIFFEID unset", func(params *SVIDParams) {
		params.SPIFFEID = spiffeid.ID{}
	})

	assertBad("PublicKey unset", func(params *SVIDParams) {
		params.PublicKey = nil
	})

	assertBad("TTL unset or negative", func(params *SVIDParams) {
		params.TTL = 0
	})

	assertBad("TTL unset or negative", func(params *SVIDParams) {
		params.TTL = -1
	})
}

func TestExpiredAuthority(t *testing.T) {
	clk := testclock.New(testclock.WithNow(caCert.NotAfter))
	authority, err := New(caCert, caKey, WithClock(clk.Clock()))
	require.NoError(t, err)

	_, err = authority.MintX509SVID(svidParams())
	require.EqualError(t, err, "authority is expired")
}

func TestMintAndVerify(t *testing.T) {
	clk := testclock.New()

	now := clk.Now().UTC()

	mintAndVerify := func(t *testing.T, params SVIDParams, expectNotAfter time.Time) {
		authority, err := New(caCert, caKey, WithClock(clk.Clock()))
		require.NoError(t, err)

		certChain, err := authority.MintX509SVID(params)
		require.NoError(t, err)
		require.Len(t, certChain, 1)

		cert := certChain[0]

		_, err = cert.Verify(x509.VerifyOptions{
			Intermediates: x509util.NewCertPool(certChain[1:]...),
			Roots:         roots,
			CurrentTime:   now,
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
				x509.ExtKeyUsageClientAuth,
			},
		})
		assert.NoError(t, err, "certificate verification failed")

		assert.NotNil(t, cert.SerialNumber)
		assert.Equal(t, []*url.URL{workloadID.URL()}, cert.URIs)
		assert.Equal(t, pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SPIRL"},
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},     // Country
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "SPIRL"}, // Organization
				x509svid.UniqueIDAttribute(workloadID),
			},
		}, cert.Subject)
		assert.Equal(t, cert.NotBefore, now.Add(-SVIDBackdatePeriod))
		assert.Equal(t, cert.NotAfter, expectNotAfter)
		assert.NotEmpty(t, cert.SubjectKeyId)
		assert.NotEmpty(t, cert.AuthorityKeyId)
		assert.Equal(t, caCert.SubjectKeyId, cert.AuthorityKeyId)
		assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
		assert.Equal(t, []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}, cert.ExtKeyUsage)
		assert.True(t, cert.BasicConstraintsValid)
		assert.False(t, cert.IsCA)
	}

	t.Run("SVID lifetime shorter than authority", func(t *testing.T) {
		notAfter := caCert.NotAfter.Add(-time.Minute)
		params := svidParams()
		params.TTL = notAfter.Sub(now)
		mintAndVerify(t, params, notAfter)
	})

	t.Run("SVID lifetime longer than authority", func(t *testing.T) {
		notAfter := caCert.NotAfter.Add(time.Minute)
		params := svidParams()
		params.TTL = notAfter.Sub(now)
		mintAndVerify(t, params, caCert.NotAfter)
	})
}

func svidParams() SVIDParams {
	return SVIDParams{
		SPIFFEID:  workloadID,
		PublicKey: svidKey.Public(),
		TTL:       time.Minute,
	}
}
