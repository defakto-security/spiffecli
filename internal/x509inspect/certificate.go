package x509inspect

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/hako/durafmt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/inspect"
	"github.com/defakto-security/spiffecli/internal/style"
	"github.com/defakto-security/spiffecli/internal/timeutil"
	"gopkg.in/yaml.v3"
)

// Stable error codes for SpiffeIDError.
const (
	SpiffeIDErrorMultipleIDs = "MULTIPLE_SPIFFE_IDS"
	SpiffeIDErrorInvalidURI  = "INVALID_SPIFFE_URI"
)

// CertificateInfo holds the parsed fields of a single X.509 certificate.
type CertificateInfo struct {
	SpiffeID             string   `json:"spiffe_id,omitempty" yaml:"spiffe_id,omitempty"`
	TrustDomain          string   `json:"trust_domain,omitempty" yaml:"trust_domain,omitempty"`
	Path                 string   `json:"path,omitempty" yaml:"path,omitempty"`
	Subject              string   `json:"subject" yaml:"subject"`
	Issuer               string   `json:"issuer" yaml:"issuer"`
	Serial               string   `json:"serial" yaml:"serial"`
	NotBefore            string   `json:"not_before" yaml:"not_before"`
	NotAfter             string   `json:"not_after" yaml:"not_after"`
	KeyAlgorithm         string   `json:"key_algorithm" yaml:"key_algorithm"`
	SignatureAlgorithm   string   `json:"signature_algorithm" yaml:"signature_algorithm"`
	KeyUsage             []string `json:"key_usage" yaml:"key_usage"`
	ExtendedKeyUsage     []string `json:"extended_key_usage,omitempty" yaml:"extended_key_usage,omitempty"`
	IsCA                 bool     `json:"is_ca" yaml:"is_ca"`
	SubjectKeyID         string   `json:"subject_key_id,omitempty" yaml:"subject_key_id,omitempty"`
	AuthorityKeyID       string   `json:"authority_key_id,omitempty" yaml:"authority_key_id,omitempty"`
	SHA256Fingerprint    string   `json:"sha256_fingerprint" yaml:"sha256_fingerprint"`
	DNSNames             []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	IPAddresses          []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	EmailAddresses       []string `json:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
	URIs                 []string `json:"uris,omitempty" yaml:"uris,omitempty"`
	SpiffeIDError        string   `json:"spiffe_id_error,omitempty" yaml:"spiffe_id_error,omitempty"`
	SpiffeIDErrorDetail  string   `json:"spiffe_id_error_detail,omitempty" yaml:"spiffe_id_error_detail,omitempty"`
	// spiffeIDLibraryError holds the raw go-spiffe parse error for the summary renderer.
	// It is intentionally unexported and untagged so it never appears in JSON/YAML output.
	spiffeIDLibraryError string
}

// FormatMap maps format names to their formatter descriptors.
var FormatMap = map[string]inspect.Formatter[[]*x509.Certificate, X509ConvertOptions]{
	"json":    {Label: "JSON", Lexer: "json", Converter: ConvertCertsToJson},
	"yaml":    {Label: "YAML", Lexer: "yaml", Converter: ConvertCertsToYaml},
	"summary": {Label: "Summary", Lexer: "text", Converter: ConvertCertsToSummary},
	"chain":   {Label: "Chain", Lexer: "text", Converter: ConvertCertsToChain},
	"tree":    {Label: "Tree", Lexer: "text", Converter: ConvertCertsToTree},
}

var keyUsageEntries = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"},
	{x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
	{x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"},
	{x509.KeyUsageCertSign, "keyCertSign"},
	{x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"},
	{x509.KeyUsageDecipherOnly, "decipherOnly"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "ocspSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "nsServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "msKernelCodeSigning",
}

func decodeKeyUsage(usage x509.KeyUsage) []string {
	result := make([]string, 0)
	for _, entry := range keyUsageEntries {
		if usage&entry.bit != 0 {
			result = append(result, entry.name)
		}
	}
	return result
}

func decodeExtKeyUsage(ekus []x509.ExtKeyUsage) []string {
	result := make([]string, 0)
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("unknown(%d)", eku))
		}
	}
	return result
}

func keyAlgorithmString(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA P-%d", pub.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func certToInfo(cert *x509.Certificate) CertificateInfo {
	info := CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		Serial:             cert.SerialNumber.Text(16),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		KeyAlgorithm:       keyAlgorithmString(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeyUsage:           decodeKeyUsage(cert.KeyUsage),
		ExtendedKeyUsage:   decodeExtKeyUsage(cert.ExtKeyUsage),
		IsCA:               cert.IsCA,
		SHA256Fingerprint:  fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
	}

	if len(cert.SubjectKeyId) > 0 {
		info.SubjectKeyID = hex.EncodeToString(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = hex.EncodeToString(cert.AuthorityKeyId)
	}

	info.DNSNames = cert.DNSNames
	info.EmailAddresses = cert.EmailAddresses
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, uri := range cert.URIs {
		info.URIs = append(info.URIs, uri.String())
	}

	// Populate SPIFFE fields only when exactly one URI SAN parses as a valid SPIFFE ID.
	// Multiple matches are ambiguous; zero matches means no SPIFFE identity.
	var spiffeMatches []spiffeid.ID
	var firstParseErr error
	for _, uri := range cert.URIs {
		if sid, err := spiffeid.FromURI(uri); err == nil {
			spiffeMatches = append(spiffeMatches, sid)
		} else if firstParseErr == nil && uri.Scheme == "spiffe" {
			firstParseErr = err
		}
	}
	switch len(spiffeMatches) {
	case 1:
		sid := spiffeMatches[0]
		info.SpiffeID = sid.String()
		info.TrustDomain = sid.TrustDomain().String()
		info.Path = sid.Path()
	default:
		if len(spiffeMatches) > 1 {
			info.SpiffeIDError = SpiffeIDErrorMultipleIDs
			info.SpiffeIDErrorDetail = "certificate contains multiple SPIFFE IDs"
		} else if firstParseErr != nil {
			info.SpiffeIDError = SpiffeIDErrorInvalidURI
			info.SpiffeIDErrorDetail = "URI is not a valid SPIFFE ID"
			info.spiffeIDLibraryError = firstParseErr.Error()
		}
	}

	return info
}

// extractSpiffeID returns the SPIFFE ID from a cert's URI SANs, or "".
func extractSpiffeID(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if sid, err := spiffeid.FromURI(uri); err == nil {
			return sid.String()
		}
	}
	return ""
}

// ConvertCertsToJson serializes the certificate slice as a JSON array.
func ConvertCertsToJson(certs []*x509.Certificate, opts X509ConvertOptions) (string, error) {
	infos := make([]CertificateInfo, 0, len(certs))
	for _, cert := range certs {
		infos = append(infos, certToInfo(cert))
	}

	var (
		jsonBytes []byte
		err       error
	)
	if opts.Output.Indent {
		jsonBytes, err = json.MarshalIndent(infos, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(infos)
	}
	if err != nil {
		return "", fmt.Errorf("error marshaling certificates to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// ConvertCertsToYaml serializes the certificate slice as a YAML sequence.
func ConvertCertsToYaml(certs []*x509.Certificate, _ X509ConvertOptions) (string, error) {
	infos := make([]CertificateInfo, 0, len(certs))
	for _, cert := range certs {
		infos = append(infos, certToInfo(cert))
	}
	out, err := yaml.Marshal(infos)
	if err != nil {
		return "", fmt.Errorf("error marshaling certificates to YAML: %w", err)
	}
	return string(out), nil
}

// sanitizeForTerminal replaces C0 (U+0000–U+001F), DEL (U+007F), and C1
// (U+0080–U+009F) control characters with the Unicode replacement character
// (U+FFFD). Printable Unicode including non-ASCII is preserved unchanged.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F || r == 0x7F || (r >= 0x80 && r <= 0x9F) {
			return unicode.ReplacementChar
		}
		return r
	}, s)
}

// ConvertCertsToSummary produces a human-readable summary of each certificate.
func ConvertCertsToSummary(certs []*x509.Certificate, opts X509ConvertOptions) (string, error) {
	return convertCertsToSummary(certs, opts, time.Now())
}

func convertCertsToSummary(certs []*x509.Certificate, opts X509ConvertOptions, now time.Time) (string, error) {
	var sb strings.Builder

	timeZone := time.Local
	if opts.Output.TimeZone != "" {
		var err error
		timeZone, err = timeutil.LoadTimezone(opts.Output.TimeZone)
		if err != nil {
			return "", fmt.Errorf("error loading timezone: %w", err)
		}
	}

	for idx, cert := range certs {
		info := certToInfo(cert)

		if len(certs) > 1 {
			fmt.Fprintf(&sb, "Certificate %d of %d\n", idx+1, len(certs))
		}

		if info.SpiffeID != "" {
			style.WriteSummaryField(&sb, "SPIFFE ID", sanitizeForTerminal(info.SpiffeID), &opts.Output)
			style.WriteSummaryField(&sb, "Trust Domain", sanitizeForTerminal(info.TrustDomain), &opts.Output)
			if info.Path != "" {
				style.WriteSummaryField(&sb, "Path", sanitizeForTerminal(info.Path), &opts.Output)
			}
		} else if info.SpiffeIDError != "" {
			style.WriteSummaryField(&sb, "SPIFFE ID Error", sanitizeForTerminal(info.SpiffeIDError), &opts.Output)
			if info.SpiffeIDErrorDetail != "" {
				style.WriteSummaryField(&sb, "SPIFFE ID Error Detail", sanitizeForTerminal(info.SpiffeIDErrorDetail), &opts.Output)
			}
			if info.spiffeIDLibraryError != "" {
				style.WriteSummaryField(&sb, "SPIFFE ID Library Error", sanitizeForTerminal(info.spiffeIDLibraryError), &opts.Output)
			}
		}

		style.WriteSummaryField(&sb, "Subject", sanitizeForTerminal(info.Subject), &opts.Output)
		style.WriteSummaryField(&sb, "Issuer", sanitizeForTerminal(info.Issuer), &opts.Output)
		style.WriteSummaryField(&sb, "Serial", sanitizeForTerminal(info.Serial), &opts.Output)
		style.WriteSummaryField(&sb, "Key Algorithm", sanitizeForTerminal(info.KeyAlgorithm), &opts.Output)
		style.WriteSummaryField(&sb, "Signature Algorithm", sanitizeForTerminal(info.SignatureAlgorithm), &opts.Output)

		notBefore := cert.NotBefore.In(timeZone)
		notAfter := cert.NotAfter.In(timeZone)
		style.WriteSummaryField(&sb, "Not Before", sanitizeForTerminal(notBefore.String()), &opts.Output)

		if cert.NotAfter.Before(now) {
			style.WriteSummaryField(&sb, "Expired at", sanitizeForTerminal(notAfter.String()), &opts.Output)
		} else {
			remaining := cert.NotAfter.Sub(now)
			fmt.Fprintf(&sb, "Expires in %s\n", sanitizeForTerminal(durafmt.Parse(remaining).LimitFirstN(2).String()))
		}

		if len(info.KeyUsage) > 0 {
			style.WriteSummaryField(&sb, "Key Usage", sanitizeForTerminal(strings.Join(info.KeyUsage, ", ")), &opts.Output)
		}
		if len(info.ExtendedKeyUsage) > 0 {
			style.WriteSummaryField(&sb, "Extended Key Usage", sanitizeForTerminal(strings.Join(info.ExtendedKeyUsage, ", ")), &opts.Output)
		}
		isCAStr := "false"
		if info.IsCA {
			isCAStr = "true"
		}
		style.WriteSummaryField(&sb, "Is CA", isCAStr, &opts.Output)
		style.WriteSummaryField(&sb, "SHA-256 Fingerprint", sanitizeForTerminal(info.SHA256Fingerprint), &opts.Output)
		if info.SubjectKeyID != "" {
			style.WriteSummaryField(&sb, "Subject Key ID", sanitizeForTerminal(info.SubjectKeyID), &opts.Output)
		}
		if info.AuthorityKeyID != "" {
			style.WriteSummaryField(&sb, "Authority Key ID", sanitizeForTerminal(info.AuthorityKeyID), &opts.Output)
		}

		if len(cert.DNSNames) > 0 {
			style.WriteSummaryField(&sb, "DNS Names", sanitizeForTerminal(strings.Join(cert.DNSNames, ", ")), &opts.Output)
		}
		if len(info.IPAddresses) > 0 {
			style.WriteSummaryField(&sb, "IP Addresses", sanitizeForTerminal(strings.Join(info.IPAddresses, ", ")), &opts.Output)
		}
		if len(cert.EmailAddresses) > 0 {
			style.WriteSummaryField(&sb, "Email Addresses", sanitizeForTerminal(strings.Join(cert.EmailAddresses, ", ")), &opts.Output)
		}
		if len(info.URIs) > 0 {
			style.WriteSummaryField(&sb, "URIs", sanitizeForTerminal(strings.Join(info.URIs, ", ")), &opts.Output)
		}

		if idx < len(certs)-1 {
			sb.WriteString("\n")
		}
	}

	return sb.String(), nil
}
