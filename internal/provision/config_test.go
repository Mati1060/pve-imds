package provision

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

func TestFromConfig(t *testing.T) {
	cfg := config.Default().PXE
	cfg.Enabled = true
	cfg.ManifestURL = "https://rgw.example.com/pxe/manifest.json"
	cfg.ChainAllowedPrefixes = []string{talosPrefix}
	conn := config.SecretsConfig{Address: "https://bao:8200", TokenFile: "/run/token"}

	_, err := FromConfig(cfg, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.NoError(t, err)

	c := cfg
	c.ManifestURL = ""
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "manifest_url")

	c = cfg
	c.ManifestURL = "http://rgw.example.com/pxe/manifest.json"
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "https")

	c = cfg
	c.ChainAllowedPrefixes = []string{"http://pxe.factory.talos.dev/pxe/"}
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "chain_allowed_prefixes")

	c = cfg
	c.ChainAllowedPrefixes = []string{"https://pxe.factory.talos.dev/pxe"}
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "must end with /")
}

func TestFromConfigImageBucket(t *testing.T) {
	cfg := config.Default().PXE
	cfg.Enabled = true
	cfg.ManifestURL = "https://rgw.example.com/pxe-images/manifest.json"
	cfg.Images.BucketURL = "https://rgw.example.com/pxe-images/"
	conn := config.SecretsConfig{Address: "https://bao:8200", TokenFile: "/run/token"}

	p, err := FromConfig(cfg, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.NoError(t, err)
	require.NotNil(t, p.opts.Images)
	assert.Equal(t, "https://rgw.example.com/pxe-images/", p.opts.Manifests.(*HTTPManifest).parse.DiskURLPrefix)
	assert.NotNil(t, p.opts.Manifests.(*HTTPManifest).sign)

	c := cfg
	c.ManifestURL = "https://rgw.example.com/pxe/manifest.json"
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "must be in pxe.images.bucket_url")

	c = cfg
	c.Images.BucketURL = "https://rgw.example.com/pxe-images"
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "must end with /")

	_, err = FromConfig(cfg, config.SecretsConfig{}, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "secrets.address")

	c = cfg
	c.Images.URLLifetime = 0
	_, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.ErrorContains(t, err, "url_lifetime")

	// Without a bucket, nothing is signed.
	c = cfg
	c.Images.BucketURL = ""
	p, err = FromConfig(c, conn, &fakeStore{}, "/pxe/live.efi", nil)
	require.NoError(t, err)
	assert.Nil(t, p.opts.Images)
	assert.Nil(t, p.opts.Manifests.(*HTTPManifest).sign)
}
