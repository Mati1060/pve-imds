package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultTmpl = "kv/data/pve-imds/pools/{pool}/{name}"
	tagTmpl     = "kv/data/pve-imds/tags/{tag}/{name}"
)

func pool(name string) Scope { return Scope{Kind: ScopePool, Name: name} }
func tag(name string) Scope  { return Scope{Kind: ScopeTag, Name: name} }

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

func TestValidateScopePool(t *testing.T) {
	for _, ok := range []string{"k8s-dmz-01", "a.b_c", "a/b", "a/b/c"} {
		assert.NoError(t, ValidateScope(pool(ok)), ok)
	}
	for _, bad := range []string{"", "a/b/c/d", "a//b", "/a", "a/", "..", "a/..", "./a", "a b", "a%2F", "a+b"} {
		assert.ErrorIs(t, ValidateScope(pool(bad)), ErrInvalidScope, bad)
	}
}

func TestValidateScopeTag(t *testing.T) {
	for _, ok := range []string{"k8s-dmz-01", "a.b_c", "c++", "UPPER"} {
		assert.NoError(t, ValidateScope(tag(ok)), ok)
	}
	for _, bad := range []string{"", "a/b", "..", ".", "a b", "a%2F", "a;b", "a,b"} {
		assert.ErrorIs(t, ValidateScope(tag(bad)), ErrInvalidScope, bad)
	}
}

func TestValidateScopeUnknownKind(t *testing.T) {
	assert.ErrorIs(t, ValidateScope(Scope{Kind: "vm", Name: "100"}), ErrInvalidScope)
}

func TestTemplateScope(t *testing.T) {
	kind, err := TemplateScope(defaultTmpl)
	require.NoError(t, err)
	assert.Equal(t, ScopePool, kind)

	kind, err = TemplateScope(tagTmpl)
	require.NoError(t, err)
	assert.Equal(t, ScopeTag, kind)

	kind, err = TemplateScope("infra/kv/data/clusters/a/{pool}/x/{name}")
	require.NoError(t, err)
	assert.Equal(t, ScopePool, kind)

	for _, bad := range []string{
		"kv/data/{name}",                      // no scope
		"kv/data/{pool}",                      // no name
		"kv/data/{pool}/{tag}/{name}",         // both scopes
		"kv/data/{pve_cluster}/{pool}/{name}", // unknown variable
		"kv/data/{vmid}/{name}",               // unknown variable
	} {
		_, err := TemplateScope(bad)
		assert.Error(t, err, bad)
	}
}

func TestBuildPath(t *testing.T) {
	p, err := BuildPath(defaultTmpl, pool("k8s-dmz-01"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/k8s-dmz-01/worker", p)
}

func TestBuildPathTag(t *testing.T) {
	p, err := BuildPath(tagTmpl, tag("k8s-dmz-01"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/tags/k8s-dmz-01/worker", p)

	p, err = BuildPath(tagTmpl, tag("c++"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/tags/c++/worker", p)
}

func TestBuildPathNestedPool(t *testing.T) {
	p, err := BuildPath(defaultTmpl, pool("dc1/k8s/dmz"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/dc1/k8s/dmz/worker", p)
}

func TestBuildPathTrimsSlashes(t *testing.T) {
	p, err := BuildPath("/"+defaultTmpl+"/", pool("p"), "s")
	require.NoError(t, err)
	assert.Equal(t, "kv/data/pve-imds/pools/p/s", p)
}

func TestBuildPathScopeKindMismatch(t *testing.T) {
	_, err := BuildPath(defaultTmpl, tag("k8s-dmz-01"), "worker")
	assert.ErrorIs(t, err, ErrInvalidScope)
	_, err = BuildPath(tagTmpl, pool("k8s-dmz-01"), "worker")
	assert.ErrorIs(t, err, ErrInvalidScope)
}

func TestBuildPathEscapeAttempts(t *testing.T) {
	for _, set := range []string{"../other-pool/worker", "..", "a/b", "%2e%2e", "x?y", "x#y"} {
		_, err := BuildPath(defaultTmpl, pool("k8s-dmz-01"), set)
		assert.ErrorIs(t, err, ErrInvalidSetName, set)
		_, err = BuildPath(tagTmpl, tag("k8s-dmz-01"), set)
		assert.ErrorIs(t, err, ErrInvalidSetName, set)
	}
	for _, p := range []string{"..", "a/..", "../b", ""} {
		_, err := BuildPath(defaultTmpl, pool(p), "worker")
		assert.ErrorIs(t, err, ErrInvalidScope, p)
	}
	for _, tg := range []string{"..", "a/b", "../b", ""} {
		_, err := BuildPath(tagTmpl, tag(tg), "worker")
		assert.ErrorIs(t, err, ErrInvalidScope, tg)
	}
}
