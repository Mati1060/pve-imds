package pvetags

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func registry(t *testing.T, content string) *Registry {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, DefaultDatacenterCfgPath, []byte(content), 0o640))
	return New(fs, DefaultDatacenterCfgPath)
}

func TestIsRegistered(t *testing.T) {
	r := registry(t, "keyboard: en-us\nregistered-tags: pve-imds-k8s-dmz-01;prod\nuser-tag-access: user-allow=free\n")

	for _, tag := range []string{"pve-imds-k8s-dmz-01", "prod", "PROD"} {
		ok, err := r.IsRegistered(tag)
		require.NoError(t, err)
		assert.True(t, ok, tag)
	}
	for _, tag := range []string{"pve-imds-k8s-dmz-02", "pro", "", "pve-imds-k8s-dmz-01;prod"} {
		ok, err := r.IsRegistered(tag)
		require.NoError(t, err)
		assert.False(t, ok, tag)
	}
}

func TestIsRegisteredCaseSensitive(t *testing.T) {
	r := registry(t, "tag-style: shape=circle,case-sensitive=1\nregistered-tags: Prod\n")

	ok, err := r.IsRegistered("Prod")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.IsRegistered("prod")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIsRegisteredNoneRegistered(t *testing.T) {
	r := registry(t, "keyboard: en-us\n")
	ok, err := r.IsRegistered("prod")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIsRegisteredMissingFile(t *testing.T) {
	r := New(afero.NewMemMapFs(), DefaultDatacenterCfgPath)
	ok, err := r.IsRegistered("prod")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestIsRegisteredReflectsChanges(t *testing.T) {
	fs := afero.NewMemMapFs()
	r := New(fs, DefaultDatacenterCfgPath)
	require.NoError(t, afero.WriteFile(fs, DefaultDatacenterCfgPath, []byte("registered-tags: a\n"), 0o640))

	ok, _ := r.IsRegistered("b")
	assert.False(t, ok)

	require.NoError(t, afero.WriteFile(fs, DefaultDatacenterCfgPath, []byte("registered-tags: a;b\n"), 0o640))
	ok, _ = r.IsRegistered("b")
	assert.True(t, ok)
}
