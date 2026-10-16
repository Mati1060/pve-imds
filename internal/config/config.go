// SPDX-FileCopyrightText: 2026 Wyatt Anderson
// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: MIT AND AGPL-3.0-or-later

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

// PXEConfig holds configuration for the /pxe endpoint, which tells iPXE
// whether to provision a VM or boot from disk. Provisioning state is kept in
// OpenBao, reached with the connection settings of [SecretsConfig].
type PXEConfig struct {
	// Enabled serves GET /pxe. It does not require Secrets.Enabled, but
	// Secrets.Address and Secrets.TokenFile must be set. Default: false.
	Enabled bool `mapstructure:"enabled"`
	// StatePathTemplate is the API path (below /v1/) of a VM's provisioning
	// record. It must contain {uuid}, the VM's SMBIOS UUID. Default:
	// kv/data/pve-imds/pxe/{uuid}.
	StatePathTemplate string `mapstructure:"state_path_template"`
	// ManifestURL is the https URL of the image manifest. Required when
	// Enabled.
	ManifestURL string `mapstructure:"manifest_url"`
	// ManifestCAFile is a PEM bundle used to verify the manifest server.
	// Empty means the system trust store.
	ManifestCAFile string `mapstructure:"manifest_ca_file"`
	// ManifestTTL is how long a fetched manifest is reused. Default: 60s.
	ManifestTTL time.Duration `mapstructure:"manifest_ttl"`
	// LiveUKI is the live OS UKI that writes disk images. It is read on
	// every request, so it can be replaced without a restart. Default:
	// /var/lib/pve-imds/live.efi.
	LiveUKI string `mapstructure:"live_uki"`
	// ChainAllowedPrefixes are the URL prefixes chain images may use. Each
	// must be https and end with "/". Default: none.
	ChainAllowedPrefixes []string `mapstructure:"chain_allowed_prefixes"`
	// Images configures a private S3 bucket for disk images and the
	// manifest.
	Images PXEImagesConfig `mapstructure:"images"`
}

// PXEImagesConfig configures a private S3 (Ceph RGW) bucket that holds the
// manifest and the disk images. When BucketURL is set, the manifest is
// fetched with signed requests, every disk image URL must be in the
// bucket, and /pxe/job hands out short-lived presigned URLs. The access
// keys are read from OpenBao with the connection settings of
// [SecretsConfig].
type PXEImagesConfig struct {
	// BucketURL is the bucket's https URL ending in "/", e.g.
	// https://rgw.example.com/pxe-images/. Empty disables signing: the
	// manifest and images are fetched without credentials. Default: empty.
	BucketURL string `mapstructure:"bucket_url"`
	// Region is the SigV4 region. RGW accepts its zonegroup name. Default:
	// "default".
	Region string `mapstructure:"region"`
	// CredentialsPath is the API path (below /v1/) of a KV v2 entry with
	// the string fields access_key and secret_key of a read-only user.
	// Default: kv/data/pve-imds/rgw-images.
	CredentialsPath string `mapstructure:"credentials_path"`
	// URLLifetime is how long a presigned image URL is valid. S3 only
	// checks it when a download starts. Default: 15m.
	URLLifetime time.Duration `mapstructure:"url_lifetime"`
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
	// PXE holds configuration for the /pxe endpoint.
	PXE PXEConfig `mapstructure:"pxe"`
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
		PXE: PXEConfig{
			StatePathTemplate: "kv/data/pve-imds/pxe/{uuid}",
			ManifestTTL:       60 * time.Second,
			LiveUKI:           "/var/lib/pve-imds/live.efi",
			Images: PXEImagesConfig{
				Region:          "default",
				CredentialsPath: "kv/data/pve-imds/rgw-images",
				URLLifetime:     15 * time.Minute,
			},
		},
	}
}
