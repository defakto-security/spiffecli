package wlapi

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/defakto-security/spiffecli/internal/stringtime"
)

const (
	DefaultX509AuthorityTTL = time.Hour * 24
	DefaultJWTAuthorityTTL  = time.Hour * 24

	DefaultWorkloadX509SVIDTTL      = time.Hour
	DefaultWorkloadX509SVIDRotateAt = time.Minute * 10

	DefaultWorkloadJWTSVIDTTL = time.Hour
)

type Config struct {
	TrustDomains []TrustDomainConfig
	Federation   FederationConfig
}

type TrustDomainConfig struct {
	Name spiffeid.TrustDomain

	X509AuthorityTTL time.Duration
	JWTAuthorityTTL  time.Duration

	Workloads []WorkloadConfig
}

type FederationConfig struct {
	Port int
}

type WorkloadConfig struct {
	ID         spiffeid.ID
	SocketPath string

	X509SVIDTTL      time.Duration
	X509SVIDRotateAt time.Duration

	JWTSVIDTTL time.Duration
}

type configTOML struct {
	TrustDomains map[spiffeid.TrustDomain]trustDomainTOML `toml:"td"`
	Federation   federationTOML
}

type federationTOML struct {
	Port int `toml:"port"`
}

type trustDomainTOML struct {
	X509AuthorityTTL stringtime.Duration     `toml:"x509_authority_ttl"`
	JWTAuthorityTTL  stringtime.Duration     `toml:"jwt_authority_ttl"`
	Workloads        map[string]workloadTOML `toml:"workload"`
}

type workloadTOML struct {
	IDPath           string              `toml:"id_path"`
	SocketPath       string              `toml:"socket_path"`
	X509SVIDTTL      stringtime.Duration `toml:"x509_svid_ttl"`
	X509SVIDRotateAt stringtime.Duration `toml:"x509_svid_rotate_at"`
	JWTSVIDTTL       stringtime.Duration `toml:"jwt_svid_ttl"`
}

func LoadConfig(configPath string) (Config, error) {
	configBytes, err := os.ReadFile(configPath) //nolint:gosec // user-provided config path
	if err != nil {
		return Config{}, errors.Wrap(err, "reading config file")
	}

	var configToml configTOML
	d := toml.NewDecoder(bytes.NewReader(configBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(&configToml); err != nil {
		var details *toml.StrictMissingError
		if errors.As(err, &details) {
			log.Println(details.String())
		}
		return Config{}, errors.Wrap(err, "decoding config")
	}

	config := Config{
		Federation: FederationConfig{
			Port: configToml.Federation.Port,
		},
	}

	for tdName, tdConfigToml := range configToml.TrustDomains {
		tdConfig := TrustDomainConfig{
			Name:             tdName,
			X509AuthorityTTL: time.Duration(tdConfigToml.X509AuthorityTTL),
			JWTAuthorityTTL:  time.Duration(tdConfigToml.JWTAuthorityTTL),
		}
		if tdConfig.X509AuthorityTTL == 0 {
			tdConfig.X509AuthorityTTL = DefaultX509AuthorityTTL
		}
		if tdConfig.JWTAuthorityTTL == 0 {
			tdConfig.JWTAuthorityTTL = DefaultJWTAuthorityTTL
		}

		for wlName, wlConfigToml := range tdConfigToml.Workloads {
			if err := spiffeid.ValidatePathSegment(wlName); err != nil {
				return Config{}, fmt.Errorf("[%s] invalid workload name %q: %v", tdName, wlName, err)
			}

			idPath := "/" + wlName
			if wlConfigToml.IDPath != "" {
				idPath = wlConfigToml.IDPath
			}
			if err := spiffeid.ValidatePath(idPath); err != nil {
				return Config{}, fmt.Errorf("[%s] invalid id_path %q for workload %s: %v", tdName, idPath, wlName, err)
			}

			socketName := wlName + ".sock"
			socketPath := filepath.Join(os.TempDir(), "spirl-dev", tdName.String(), socketName)
			if wlConfigToml.SocketPath != "" {
				socketPath = wlConfigToml.SocketPath
			}

			id, err := spiffeid.FromPath(tdName, idPath)
			if err != nil {
				// unexpected since we've validated everything
				return Config{}, fmt.Errorf("[%s] invalid workload ID for %s: %v", tdName, wlName, err)
			}

			wlConfig := WorkloadConfig{
				ID:               id,
				SocketPath:       socketPath,
				X509SVIDTTL:      time.Duration(wlConfigToml.X509SVIDTTL),
				X509SVIDRotateAt: time.Duration(wlConfigToml.X509SVIDRotateAt),
				JWTSVIDTTL:       time.Duration(wlConfigToml.JWTSVIDTTL),
			}

			if wlConfig.X509SVIDTTL == 0 {
				wlConfig.X509SVIDTTL = DefaultWorkloadX509SVIDTTL
			}
			if wlConfig.X509SVIDRotateAt == 0 {
				wlConfig.X509SVIDRotateAt = DefaultWorkloadX509SVIDRotateAt
			}
			if wlConfig.JWTSVIDTTL == 0 {
				wlConfig.JWTSVIDTTL = DefaultWorkloadJWTSVIDTTL
			}

			tdConfig.Workloads = append(tdConfig.Workloads, wlConfig)
		}
		config.TrustDomains = append(config.TrustDomains, tdConfig)
	}

	return config, nil
}
