// Package config defines the pve-imds configuration structure and defaults.
package config

import (
	"os"
	"time"
)

// JWTSVIDConfig holds configuration for JWT-SVID issuance and JWKS serving.
type JWTSVIDConfig struct {
	// PrivateKeyPath is the path to the node's PEM-encoded RSA private key.
	// When using systemd credentials, set this to
	// /run/credentials/pve-imds.service/pve-ssl.key.
	PrivateKeyPath string `mapstructure:"private_key_path"`
	// TokenTTL is the lifetime of issued JWT-SVIDs. Default: 5 minutes.
	TokenTTL time.Duration `mapstructure:"token_ttl"`
	// NodesDir is the directory containing per-node PVE SSL certificates used
	// to build the JWKS response. Each subdirectory must contain pve-ssl.pem.
	NodesDir string `mapstructure:"nodes_dir"`
	// TrustDomain is the SPIFFE trust domain used in the sub claim, e.g.
	// "pve.example.com". Defaults to the node's hostname.
	TrustDomain string `mapstructure:"trust_domain"`
}

// NoCloudConfig holds configuration for the NoCloud datasource endpoint.
type NoCloudConfig struct {
	// Enabled serves the NoCloud datasource under /nocloud/. Default: true.
	Enabled bool `mapstructure:"enabled"`
}

// SecretsConfig holds configuration for rendering templated user-data with
// secrets read from an OpenBao/Vault KV v2 secrets engine.
type SecretsConfig struct {
	// Enabled turns on {{ secret "field" }} rendering for user-data blocks
	// that declare secrets=<set>. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// Address is the base URL of the OpenBao/Vault server, e.g.
	// "https://openbao.example.com:8200". Must use https.
	Address string `mapstructure:"address"`
	// Namespace is sent as X-Vault-Namespace on every request. Empty means
	// the root namespace.
	Namespace string `mapstructure:"namespace"`
	// CAFile is a PEM bundle used to verify the server certificate. Empty
	// means the system trust store.
	CAFile string `mapstructure:"ca_file"`
	// TokenFile holds the token, typically maintained by OpenBao Agent. It is
	// re-read on every request so token rotation needs no restart.
	TokenFile string `mapstructure:"token_file"`
	// PathTemplate is the API path (below /v1/) of a secret set. It must
	// contain {name} and exactly one of {pool} (scope secrets by resource
	// pool) or {tag} (scope secrets by VM tag). Default:
	// kv/data/pve-imds/pools/{pool}/{name}.
	PathTemplate string `mapstructure:"path_template"`
	// TagPrefix marks the VM tag that selects the secret scope when
	// PathTemplate uses {tag}: a VM tagged "<prefix>k8s" uses scope "k8s".
	// Default: "pve-imds-".
	TagPrefix string `mapstructure:"tag_prefix"`
	// RequireRegisteredTags only accepts scope tags listed in
	// registered-tags in /etc/pve/datacenter.cfg, which only users with
	// Sys.Modify on "/" can set. Default: true.
	RequireRegisteredTags bool `mapstructure:"require_registered_tags"`
	// CacheTTL is how long a fetched secret set is reused. Default: 60s.
	CacheTTL time.Duration `mapstructure:"cache_ttl"`
}

// Config holds all pve-imds configuration.
type Config struct {
	// LogLevel is the minimum log level to emit (debug, info, warn, error).
	LogLevel string `mapstructure:"log_level"`
	// FxLogging enables fx lifecycle logging.
	FxLogging bool `mapstructure:"fx_logging"`
	// Emulate selects the IMDS emulation target (ec2, openstack).
	Emulate string `mapstructure:"emulate"`
	// PprofAddr is the address to serve pprof endpoints; disabled if empty.
	PprofAddr string `mapstructure:"pprof_addr"`
	// MetricsAddr is the address to serve Prometheus metrics; disabled if empty.
	MetricsAddr string `mapstructure:"metrics_addr"`
	// JWTSVID holds configuration for JWT-SVID issuance and JWKS serving.
	JWTSVID JWTSVIDConfig `mapstructure:"jwtsvid"`
	// NoCloud holds configuration for the NoCloud datasource endpoint.
	NoCloud NoCloudConfig `mapstructure:"nocloud"`
	// Secrets holds configuration for templated user-data.
	Secrets SecretsConfig `mapstructure:"secrets"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	hostname, _ := os.Hostname()
	return Config{
		LogLevel: "info",
		Emulate:  "openstack",
		JWTSVID: JWTSVIDConfig{
			PrivateKeyPath: "/etc/pve/local/pve-ssl.key",
			TokenTTL:       5 * time.Minute,
			NodesDir:       "/etc/pve/nodes",
			TrustDomain:    hostname,
		},
		NoCloud: NoCloudConfig{
			Enabled: true,
		},
		Secrets: SecretsConfig{
			PathTemplate:          "kv/data/pve-imds/pools/{pool}/{name}",
			TagPrefix:             "pve-imds-",
			RequireRegisteredTags: true,
			CacheTTL:              60 * time.Second,
		},
	}
}
