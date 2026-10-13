package provision

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

func TestFromConfig(t *testing.T) {
	cfg := config.Default().PXE
	cfg.Enabled = true
	cfg.ManifestURL = "https://rgw.example.com/pxe/manifest.json"
	cfg.ChainAllowedPrefixes = []string{talosPrefix}

	_, err := FromConfig(cfg, &fakeStore{}, "/pxe/live.efi", nil)
	require.NoError(t, err)

	c := cfg
	c.ManifestURL = ""
	_, err = FromConfig(c, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "manifest_url")

	c = cfg
	c.ManifestURL = "http://rgw.example.com/pxe/manifest.json"
	_, err = FromConfig(c, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "https")

	c = cfg
	c.ChainAllowedPrefixes = []string{"http://pxe.factory.talos.dev/pxe/"}
	_, err = FromConfig(c, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "chain_allowed_prefixes")

	c = cfg
	c.ChainAllowedPrefixes = []string{"https://pxe.factory.talos.dev/pxe"}
	_, err = FromConfig(c, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "must end with /")
}
