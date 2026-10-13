package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

func loadConfig(t *testing.T, yaml string) config.Config {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)

	path := ""
	if yaml != "" {
		path = filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	}
	require.NoError(t, initConfig(path))

	var cfg config.Config
	require.NoError(t, viper.Unmarshal(&cfg))
	return cfg
}

func TestConfigDefaults(t *testing.T) {
	cfg := loadConfig(t, "")
	assert.True(t, cfg.NoCloud.Enabled)
	assert.False(t, cfg.Secrets.Enabled)
	assert.Equal(t, "kv/data/pve-imds/pools/{pool}/{name}", cfg.Secrets.PathTemplate)
	assert.Equal(t, "pve-imds-", cfg.Secrets.TagPrefix)
	assert.True(t, cfg.Secrets.RequireRegisteredTags)
	assert.Equal(t, 60*time.Second, cfg.Secrets.CacheTTL)
	assert.False(t, cfg.PXE.Enabled)
	assert.Equal(t, "kv/data/pve-imds/pxe/{uuid}", cfg.PXE.StatePathTemplate)
	assert.Equal(t, 60*time.Second, cfg.PXE.ManifestTTL)
	assert.Equal(t, "/var/lib/pve-imds/live.efi", cfg.PXE.LiveUKI)
	assert.Empty(t, cfg.PXE.ManifestURL)
	assert.Empty(t, cfg.PXE.ChainAllowedPrefixes)
}

func TestConfigFile(t *testing.T) {
	cfg := loadConfig(t, `
nocloud:
  enabled: false
secrets:
  enabled: true
  address: https://bao.example.com:8200
  namespace: pve-cluster-a
  ca_file: /etc/pve-imds/ca.pem
  token_file: /run/openbao-agent-pve-imds/token
  path_template: kv/data/x/{tag}/{name}
  tag_prefix: secrets-
  require_registered_tags: false
  cache_ttl: 15s
pxe:
  enabled: true
  state_path_template: secret/data/pxe/{uuid}
  manifest_url: https://rgw.example.com/pxe/manifest.json
  manifest_ca_file: /etc/pve-imds/rgw-ca.pem
  manifest_ttl: 30s
  live_uki: /srv/live.efi
  chain_allowed_prefixes:
    - https://pxe.factory.talos.dev/pxe/
    - https://boot.example.com/
`)
	assert.False(t, cfg.NoCloud.Enabled)
	assert.Equal(t, config.SecretsConfig{
		Enabled:               true,
		Address:               "https://bao.example.com:8200",
		Namespace:             "pve-cluster-a",
		CAFile:                "/etc/pve-imds/ca.pem",
		TokenFile:             "/run/openbao-agent-pve-imds/token",
		PathTemplate:          "kv/data/x/{tag}/{name}",
		TagPrefix:             "secrets-",
		RequireRegisteredTags: false,
		CacheTTL:              15 * time.Second,
	}, cfg.Secrets)
	assert.Equal(t, config.PXEConfig{
		Enabled:           true,
		StatePathTemplate: "secret/data/pxe/{uuid}",
		ManifestURL:       "https://rgw.example.com/pxe/manifest.json",
		ManifestCAFile:    "/etc/pve-imds/rgw-ca.pem",
		ManifestTTL:       30 * time.Second,
		LiveUKI:           "/srv/live.efi",
		ChainAllowedPrefixes: []string{
			"https://pxe.factory.talos.dev/pxe/",
			"https://boot.example.com/",
		},
	}, cfg.PXE)
}

func TestConfigEnv(t *testing.T) {
	t.Setenv("PVE_IMDS_SECRETS_ENABLED", "true")
	t.Setenv("PVE_IMDS_SECRETS_NAMESPACE", "ns1")
	t.Setenv("PVE_IMDS_NOCLOUD_ENABLED", "false")
	t.Setenv("PVE_IMDS_PXE_ENABLED", "true")
	t.Setenv("PVE_IMDS_PXE_STATE_PATH_TEMPLATE", "kv/data/x/{uuid}")
	t.Setenv("PVE_IMDS_PXE_MANIFEST_URL", "https://rgw.example.com/m.json")
	t.Setenv("PVE_IMDS_PXE_CHAIN_ALLOWED_PREFIXES", "https://a.example.com/,https://b.example.com/")
	cfg := loadConfig(t, "")
	assert.True(t, cfg.Secrets.Enabled)
	assert.Equal(t, "ns1", cfg.Secrets.Namespace)
	assert.False(t, cfg.NoCloud.Enabled)
	assert.True(t, cfg.PXE.Enabled)
	assert.Equal(t, "kv/data/x/{uuid}", cfg.PXE.StatePathTemplate)
	assert.Equal(t, "https://rgw.example.com/m.json", cfg.PXE.ManifestURL)
	assert.Equal(t, []string{"https://a.example.com/", "https://b.example.com/"}, cfg.PXE.ChainAllowedPrefixes)
}
