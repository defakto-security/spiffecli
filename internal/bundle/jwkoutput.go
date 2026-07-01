package bundle

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss/tree"
	"github.com/go-jose/go-jose/v4"
	"github.com/defakto-security/spiffecli/internal/inspect"
	"github.com/defakto-security/spiffecli/internal/style"
	"gopkg.in/yaml.v3"
)

// These functions assume that the inspector has already checked that the JWKS has at least one key.
var FormatMap = map[string]inspect.Formatter[*jose.JSONWebKeySet, BundleOutputOptions]{
	"json":    {Label: "JSON", Lexer: "json", Converter: ConvertBundleToJson},
	"yaml":    {Label: "YAML", Lexer: "yaml", Converter: ConvertBundleToYaml},
	"summary": {Label: "Summary", Lexer: "text", Converter: ConvertBundleToSummary},
	"key-ids": {Label: "Key IDs", Lexer: "text", Converter: ConvertBundleToKeyIDs},
}

func ConvertBundleToJson(jwks *jose.JSONWebKeySet, options BundleOutputOptions) (string, error) {
	var jsonBytes []byte
	var err error
	if options.Indent {
		jsonBytes, err = json.MarshalIndent(jwks, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(jwks)
	}

	if err != nil {
		return "", fmt.Errorf("error marshaling JWKS to JSON: %w", err)
	}
	return string(jsonBytes), nil
}

func ConvertBundleToYaml(jwks *jose.JSONWebKeySet, options BundleOutputOptions) (string, error) {
	// First marshal JWKS to a map to ensure proper YAML structure
	var intermediate map[string]interface{}

	jsonData, err := json.Marshal(jwks)
	if err != nil {
		return "", fmt.Errorf("error converting JWKS to JSON: %w", err)
	}
	if err := json.Unmarshal(jsonData, &intermediate); err != nil {
		return "", fmt.Errorf("error converting JWKS to intermediate map: %w", err)
	}
	yamlBytes, err := yaml.Marshal(intermediate)
	if err != nil {
		return "", fmt.Errorf("error converting intermediate map to YAML: %w", err)
	}

	return string(yamlBytes), nil
}

func ConvertBundleToKeyIDs(jwks *jose.JSONWebKeySet, options BundleOutputOptions) (string, error) {
	var keyIDs strings.Builder
	for i, key := range jwks.Keys {
		if key.KeyID == "" {
			return "", fmt.Errorf("key ID is missing from key %d", i)
		}
		keyIDs.WriteString(key.KeyID)
		keyIDs.WriteString("\n")
	}
	return keyIDs.String(), nil
}

func ConvertBundleToSummary(jwks *jose.JSONWebKeySet, options BundleOutputOptions) (string, error) {
	var summary strings.Builder
	var ct string

	switch len(jwks.Keys) {
	case 1:
		ct = "One key found"
	default:
		ct = fmt.Sprintf("Found %d keys", len(jwks.Keys))
	}

	t := tree.Root(style.GetLabel(ct, &options))

	for _, key := range jwks.Keys {
		keyType, keyDescriber, keyDescription := summarizeKeyType(&key)
		t.Child(tree.New().
			Root(style.GetSummaryField("Key ID", key.KeyID, &options)).
			Child(style.GetSummaryField("Key Type", keyType, &options)).
			Child(style.GetSummaryField(keyDescriber, keyDescription, &options)).
			Child(style.GetSummaryField("Use", summarizeKeyUsage(&key), &options)))

	}
	summary.WriteString(t.String())
	summary.WriteString("\n")

	return summary.String(), nil
}

func summarizeKeyType(jwk *jose.JSONWebKey) (string, string, string) {
	// Taken from jose documentation:
	// Key is the Go in-memory representation of this key. It must have one
	// of these types:
	//  - ed25519.PublicKey
	//  - ed25519.PrivateKey
	//  - *ecdsa.PublicKey
	//  - *ecdsa.PrivateKey
	//  - *rsa.PublicKey
	//  - *rsa.PrivateKey
	//  - []byte (a symmetric key)
	//
	switch kt := jwk.Key.(type) {
	case *rsa.PublicKey:
		k := jwk.Key.(*rsa.PublicKey)
		return "RSA", "Key Size", fmt.Sprintf("%d", k.N.BitLen())
	case *rsa.PrivateKey:
		k := jwk.Key.(*rsa.PrivateKey)
		return "RSA", "Key Size", fmt.Sprintf("%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		k := jwk.Key.(*ecdsa.PublicKey)
		return "Elliptic Curve", "Curve", k.Curve.Params().Name
	case *ecdsa.PrivateKey:
		k := jwk.Key.(*ecdsa.PrivateKey)
		return "Elliptic Curve", "Curve", k.PublicKey.Curve.Params().Name
	case ed25519.PublicKey:
		return "Elliptic Curve", "Curve", "Ed25519"
	case ed25519.PrivateKey:
		return "Elliptic Curve", "Curve", "Ed25519"
	case []byte:
		return "Symmetric", "Key Description", "Unknown" // Symmetric key
	default:
		return fmt.Sprintf("Unknown type: %T", kt), "Key Description", "Unknown"
	}
}

func summarizeKeyUsage(jwk *jose.JSONWebKey) string {
	switch jwk.Use {
	case "sig":
		return "Signature"
	case "enc":
		return "Encryption"
	case "":
		return "Unspecified"
	default:
		return jwk.Use
	}
}
