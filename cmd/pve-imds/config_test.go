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
	assert.Equal(t, 60*time.Second, cfg.Secrets.CacheTTL)
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
  path_template: kv/data/x/{pool}/{name}
  cache_ttl: 15s
`)
	assert.False(t, cfg.NoCloud.Enabled)
	assert.Equal(t, config.SecretsConfig{
		Enabled:      true,
		Address:      "https://bao.example.com:8200",
		Namespace:    "pve-cluster-a",
		CAFile:       "/etc/pve-imds/ca.pem",
		TokenFile:    "/run/openbao-agent-pve-imds/token",
		PathTemplate: "kv/data/x/{pool}/{name}",
		CacheTTL:     15 * time.Second,
	}, cfg.Secrets)
}

func TestConfigEnv(t *testing.T) {
	t.Setenv("PVE_IMDS_SECRETS_ENABLED", "true")
	t.Setenv("PVE_IMDS_SECRETS_NAMESPACE", "ns1")
	t.Setenv("PVE_IMDS_NOCLOUD_ENABLED", "false")
	cfg := loadConfig(t, "")
	assert.True(t, cfg.Secrets.Enabled)
	assert.Equal(t, "ns1", cfg.Secrets.Namespace)
	assert.False(t, cfg.NoCloud.Enabled)
}
