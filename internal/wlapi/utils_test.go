package wlapi

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertsBytes(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := certsBytes()
		assert.Nil(t, result)
	})

	t.Run("single cert returns raw bytes", func(t *testing.T) {
		td, err := newTestTrustDomain(t, "example.com").Bundle()
		require.NoError(t, err)
		certs := td.X509Authorities()
		require.NotEmpty(t, certs)

		result := certsBytes(certs[0])
		assert.Equal(t, certs[0].Raw, result)
	})

	t.Run("multiple certs concatenates raw bytes", func(t *testing.T) {
		td1 := newTestTrustDomain(t, "example.com")
		td2 := newTestTrustDomain(t, "acme-corp.com")

		bundle1, err := td1.Bundle()
		require.NoError(t, err)
		bundle2, err := td2.Bundle()
		require.NoError(t, err)

		certs1 := bundle1.X509Authorities()
		certs2 := bundle2.X509Authorities()
		require.NotEmpty(t, certs1)
		require.NotEmpty(t, certs2)

		result := certsBytes(certs1[0], certs2[0])
		expected := append(append([]byte{}, certs1[0].Raw...), certs2[0].Raw...)
		assert.Equal(t, expected, result)
	})

	t.Run("parses back to certificate", func(t *testing.T) {
		td := newTestTrustDomain(t, "example.com")
		bundle, err := td.Bundle()
		require.NoError(t, err)
		certs := bundle.X509Authorities()
		require.NotEmpty(t, certs)

		raw := certsBytes(certs...)
		parsed, err := x509.ParseCertificates(raw)
		require.NoError(t, err)
		assert.Len(t, parsed, len(certs))
	})
}
