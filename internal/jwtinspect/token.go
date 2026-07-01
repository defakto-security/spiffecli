package jwtinspect

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss/list"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hako/durafmt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/inspect"
	"github.com/defakto-security/spiffecli/internal/style"
	"github.com/defakto-security/spiffecli/internal/timeutil"
	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
)

// Supported as per JWT-SVID spec
var SvidSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, // RSASSA-PKCS-v1.5 using SHA-256
	jose.RS384, // RSASSA-PKCS-v1.5 using SHA-384
	jose.RS512, // RSASSA-PKCS-v1.5 using SHA-512
	jose.ES256, // ECDSA using P-256 and SHA-256
	jose.ES384, // ECDSA using P-384 and SHA-384
	jose.ES512, // ECDSA using P-521 and SHA-512
	jose.PS256, // RSASSA-PSS using SHA256 and MGF1-SHA256
	jose.PS384, // RSASSA-PSS using SHA384 and MGF1-SHA384
	jose.PS512, // RSASSA-PSS using SHA512 and MGF1-SHA512
}

// This includes that are not supported by JWT-SVID
var SignatureAlgorithmDescriptions = map[jose.SignatureAlgorithm]string{
	jose.ES256: "ECDSA using P-256 curve and SHA-256",
	jose.ES384: "ECDSA using P-384 curve and SHA-384",
	jose.ES512: "ECDSA using P-521 curve and SHA-512",
	jose.RS256: "RSASSA-PKCS1-v1_5 using SHA-256",
	jose.RS384: "RSASSA-PKCS1-v1_5 using SHA-384",
	jose.RS512: "RSASSA-PKCS1-v1_5 using SHA-512",
	jose.PS256: "RSASSA-PSS using SHA-256 and MGF1-SHA-256",
	jose.PS384: "RSASSA-PSS using SHA-384 and MGF1-SHA-384",
	jose.PS512: "RSASSA-PSS using SHA-512 and MGF1-SHA-512",
	jose.EdDSA: "EdDSA using Ed25519",
	jose.HS256: "HMAC using SHA-256",
	jose.HS384: "HMAC using SHA-384",
	jose.HS512: "HMAC using SHA-512",
}

var AllSignatureAlgorithms = maps.Keys(SignatureAlgorithmDescriptions)

var FormatMap = map[string]inspect.Formatter[*jwt.JSONWebToken, JwtInspectOutputOptions]{
	"json":    {Label: "JSON", Lexer: "json", Converter: ConvertTokenToJson},
	"yaml":    {Label: "YAML", Lexer: "yaml", Converter: ConvertTokenToYaml},
	"summary": {Label: "Summary", Lexer: "text", Converter: ConvertTokenToSummary},
}

// Converting it to a map is useful for JSON and YAML output.
func convertTokenToMap(tok *jwt.JSONWebToken, options JwtInspectOutputOptions) (map[string]interface{}, error) {
	claims := make(map[string]interface{})
	err := tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT claims")
	}

	jwtMap := map[string]interface{}{
		"claims": claims,
	}

	if options.Header {
		jwtMap["headers"] = tok.Headers
	}

	return jwtMap, nil
}

func convertToStandardClaims(tok *jwt.JSONWebToken) (jwt.Claims, error) {
	var claims jwt.Claims
	err := tok.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("unable to parse JWT claims")
	}
	return claims, nil
}

func ConvertTokenToJson(tok *jwt.JSONWebToken, options JwtInspectOutputOptions) (string, error) {
	jwtMap, err := convertTokenToMap(tok, options)
	if err != nil {
		return "", fmt.Errorf("error inspecting JWT: %w", err)
	}
	var jsonBytes []byte
	if options.Indent {
		jsonBytes, err = json.MarshalIndent(jwtMap, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(jwtMap)
	}

	if err != nil {
		return "", fmt.Errorf("error marshaling JWT to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

func ConvertTokenToYaml(tok *jwt.JSONWebToken, options JwtInspectOutputOptions) (string, error) {
	jwtMap, err := convertTokenToMap(tok, options)
	if err != nil {
		return "", fmt.Errorf("error inspecting JWT: %w", err)
	}
	yamlBytes, err := yaml.Marshal(jwtMap)
	if err != nil {
		return "", fmt.Errorf("error marshaling JWT to YAML: %w", err)
	}
	return string(yamlBytes), nil
}

func ConvertTokenToSummary(tok *jwt.JSONWebToken, options JwtInspectOutputOptions) (string, error) {
	return convertTokenToSummary(tok, options, time.Now())
}

func convertTokenToSummary(tok *jwt.JSONWebToken, options JwtInspectOutputOptions, nowMeasured time.Time) (string, error) {
	var summary strings.Builder
	claims, err := convertToStandardClaims(tok)
	if err != nil {
		return "", fmt.Errorf("error inspecting JWT claims: %w", err)
	}

	isSvid, reasons, err := isSvid(tok)

	if err != nil {
		fmt.Fprintf(&summary, "Could not determine whether this is a well-formed SVID: %v\n", err)
	} else {
		if isSvid {
			summary.WriteString("Appears to be a well-formed SVID.\n")
		} else {
			style.WriteErrorMessage(&summary, "Not a well-formed SVID!", &options)
			l := list.New()

			for _, reason := range reasons {
				l.Item(reason)
			}
			summary.WriteString(style.GetErrorMessage(l.String(), &options))
			summary.WriteString("\n")
		}
	}

	timeZone := time.Local
	if options.TimeZone != "" {
		timeZone, err = timeutil.LoadTimezone(options.TimeZone)
		if err != nil {
			return "", fmt.Errorf("error loading timezone: %w", err)
		}
	}

	expiryTimeString := claims.Expiry.Time().In(timeZone).String()

	if claims.Expiry.Time().Before(nowMeasured) {
		style.WriteSummaryField(&summary, "Token expired at", expiryTimeString, &options)
	} else {
		remaining := claims.Expiry.Time().Sub(nowMeasured)
		// LimitFirstN(2) is used to limit the output to the two largest units,
		// (e.g. "59 minutes 51 seconds" instead of "59 minutes 51 seconds 803
		// milliseconds 56 microseconds")
		fmt.Fprintf(&summary, "Token expires in %s\n", durafmt.Parse(remaining).LimitFirstN(2).String())
	}
	if claims.IssuedAt != nil {
		style.WriteSummaryField(&summary, "Token issued at", claims.IssuedAt.Time().In(timeZone).String(), &options)
	}

	if claims.Subject != "" {
		sid, err := spiffeid.FromString(claims.Subject)

		if err != nil {
			style.WriteSummaryField(&summary, "Subject", claims.Subject, &options)
		} else {
			style.WriteSummaryField(&summary, "SPIFFE ID", sid.String(), &options)
			style.WriteSummaryField(&summary, "SPIFFE Trust Domain", sid.TrustDomain().String(), &options)
			style.WriteSummaryField(&summary, "SPIFFE Path", sid.Path(), &options)
		}
	}
	if claims.Issuer != "" {
		style.WriteSummaryField(&summary, "Issuer", claims.Issuer, &options)
	}

	if len(claims.Audience) > 0 {
		summary.WriteString("Audience claims:\n")
		l := list.New()
		for _, a := range claims.Audience {
			l.Item(a)
		}
		summary.WriteString(l.String())
		summary.WriteString("\n")
	}

	// For the summary, --headers has no effect
	if tok.Headers != nil {
		for _, header := range tok.Headers {
			if header.KeyID != "" {
				style.WriteSummaryField(&summary, "Key ID", header.KeyID, &options)
			}
			if header.Algorithm != "" {
				signatureAlgorithm := jose.SignatureAlgorithm(header.Algorithm)
				style.WriteSummaryField(&summary, "Signature Algorithm", SignatureAlgorithmDescriptions[signatureAlgorithm], &options)
			}
		}
	}

	return summary.String(), nil
}

// If false, the second argument will contain a list of failure reasons.
// Using https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md as the
// authoritative reference here.
func isSvid(tok *jwt.JSONWebToken) (bool, []string, error) {

	var isSvid bool
	var reasons []string

	// 1. It must use a supported signature algorithm
	var usesSupportedAlgorithm bool
	var typeHeaderCorrect bool
	if tok.Headers != nil {
		for _, header := range tok.Headers {
			if header.Algorithm != "" {
				signatureAlgorithm := jose.SignatureAlgorithm(header.Algorithm)
				if slices.Contains(SvidSignatureAlgorithms, signatureAlgorithm) {
					usesSupportedAlgorithm = true
				}
			}
			// 2. If the typ header is present, it must be "JWT" or "JOSE"
			if header.ExtraHeaders != nil {
				switch header.ExtraHeaders["typ"] {
				case "JWT", "JOSE", nil:
					typeHeaderCorrect = true
				}
			}
		}
	}
	if !usesSupportedAlgorithm {
		reasons = append(reasons, "token uses an unsupported signature algorithm")
	}
	if !typeHeaderCorrect {
		reasons = append(reasons, "token does not have a valid \"typ\" header")
	}

	// 3. The "sub" claim must be set to the SPIFFE ID of the workload
	claims, err := convertToStandardClaims(tok)
	if err != nil {
		return false, nil, fmt.Errorf("unable to parse JWT claims")
	}
	_, err = spiffeid.FromString(claims.Subject)
	if err != nil {
		reasons = append(reasons, "token does not have a valid SPIFFE ID in the \"sub\" claim")
	}

	// 4. The "aud" claim must be present
	if len(claims.Audience) == 0 {
		reasons = append(reasons, "token does not have an \"aud\" claim set with at least one value")
	}

	// 5. The "exp" claim must be present
	if claims.Expiry == nil || claims.Expiry.Time().IsZero() {
		reasons = append(reasons, "token does not have \"exp\" set correctly")
	}

	if len(reasons) == 0 {
		isSvid = true
	}

	return isSvid, reasons, nil
}
