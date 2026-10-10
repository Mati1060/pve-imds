package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultTmpl = "kv/data/pve-imds/pools/{pool}/{name}"

func TestValidateSetName(t *testing.T) {
	for _, ok := range []string{"worker", "Worker-01", "a", "cp_2", "0abc"} {
		assert.NoError(t, ValidateSetName(ok), ok)
	}
	for _, bad := range []string{
		"", "..", ".", "a/b", "../x", "x/..", "-lead", "_lead", "a.b",
		"a b", "a%2Fb", "a\\b", "é", string(make([]byte, 65)),
	} {
		assert.ErrorIs(t, ValidateSetName(bad), ErrInvalidSetName, bad)
	}
}

func TestValidatePool(t *testing.T) {
	for _, ok := range []string{"k8s-dmz-01", "a.b_c", "a/b", "a/b/c"} {
		assert.NoError(t, ValidatePool(ok), ok)
	}
	for _, bad := range []string{"", "a/b/c/d", "a//b", "/a", "a/", "..", "a/..", "./a", "a b", "a%2F"} {
		assert.ErrorIs(t, ValidatePool(bad), ErrInvalidPool, bad)
	}
}

func TestValidatePathTemplate(t *testing.T) {
	assert.NoError(t, ValidatePathTemplate(defaultTmpl))
	assert.NoError(t, ValidatePathTemplate("infra/kv/data/clusters/a/{pool}/x/{name}"))
	assert.Error(t, ValidatePathTemplate("kv/data/{name}"))
	assert.Error(t, ValidatePathTemplate("kv/data/{pool}"))
	assert.Error(t, ValidatePathTemplate("kv/data/{pve_cluster}/{pool}/{name}"))
}

func TestBuildPath(t *testing.T) {
	p, err := BuildPath(defaultTmpl, "k8s-dmz-01", "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/k8s-dmz-01/worker", p)
}

func TestBuildPathNestedPool(t *testing.T) {
	p, err := BuildPath(defaultTmpl, "dc1/k8s/dmz", "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/dc1/k8s/dmz/worker", p)
}

func TestBuildPathTrimsSlashes(t *testing.T) {
	p, err := BuildPath("/"+defaultTmpl+"/", "p", "s")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/p/s", p)
}

func TestBuildPathEscapeAttempts(t *testing.T) {
	for _, set := range []string{"../other-pool/worker", "..", "a/b", "%2e%2e", "x?y", "x#y"} {
		_, err := BuildPath(defaultTmpl, "k8s-dmz-01", set)
		assert.ErrorIs(t, err, ErrInvalidSetName, set)
	}
	for _, pool := range []string{"..", "a/..", "../b", ""} {
		_, err := BuildPath(defaultTmpl, pool, "worker")
		assert.ErrorIs(t, err, ErrInvalidPool, pool)
	}
}
