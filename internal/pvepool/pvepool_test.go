package pvepool

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// userCfg is a realistic /etc/pve/user.cfg, including nested pools (PVE 8.1+).
const userCfg = `user:root@pam:1:0:::root@example.com:::
token:root@pam!automation:0:1::
group:admins:root@pam::

pool:k8s-dmz-01:DMZ cluster:101,102:local-lvm:
pool:empty:::
pool:dc1:::
pool:dc1/k8s:Nested:201:
pool:dc1/k8s/workers::202;203 204:
pool:inv@lid::301:
acl:1:/pool/k8s-dmz-01:@admins:PVEVMAdmin:
`

func newLookup(t *testing.T, content string) (*Lookup, afero.Fs) {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, DefaultUserCfgPath, []byte(content), 0o640))
	return New(fs, DefaultUserCfgPath), fs
}

func TestPoolOf(t *testing.T) {
	l, _ := newLookup(t, userCfg)

	cases := map[int]string{
		101: "k8s-dmz-01",
		102: "k8s-dmz-01",
		201: "dc1/k8s",
		202: "dc1/k8s/workers",
		203: "dc1/k8s/workers",
		204: "dc1/k8s/workers",
	}
	for vmid, want := range cases {
		pool, ok, err := l.PoolOf(vmid)
		require.NoError(t, err)
		assert.True(t, ok, vmid)
		assert.Equal(t, want, pool, vmid)
	}
}

func TestPoolOfNotInPool(t *testing.T) {
	l, _ := newLookup(t, userCfg)

	for _, vmid := range []int{100, 1, 10, 1010} {
		_, ok, err := l.PoolOf(vmid)
		require.NoError(t, err)
		assert.False(t, ok, vmid)
	}
}

func TestPoolOfInvalidPoolIgnored(t *testing.T) {
	l, _ := newLookup(t, userCfg)

	_, ok, err := l.PoolOf(301)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPoolOfDuplicateFirstWins(t *testing.T) {
	l, _ := newLookup(t, "pool:a::5:\npool:b::5:\n")

	pool, ok, err := l.PoolOf(5)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "a", pool)
}

func TestPoolOfReflectsChanges(t *testing.T) {
	l, fs := newLookup(t, "pool:a::5:\n")

	pool, _, err := l.PoolOf(5)
	require.NoError(t, err)
	assert.Equal(t, "a", pool)

	// Moving the VM to another pool takes effect on the next lookup.
	require.NoError(t, afero.WriteFile(fs, DefaultUserCfgPath, []byte("pool:a:::\npool:b::5:\n"), 0o640))
	pool, _, err = l.PoolOf(5)
	require.NoError(t, err)
	assert.Equal(t, "b", pool)

	// Removing it from all pools does too.
	require.NoError(t, afero.WriteFile(fs, DefaultUserCfgPath, []byte("pool:a:::\npool:b:::\n"), 0o640))
	_, ok, err := l.PoolOf(5)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPoolOfMissingFile(t *testing.T) {
	l := New(afero.NewMemMapFs(), DefaultUserCfgPath)
	_, _, err := l.PoolOf(5)
	assert.Error(t, err)
}
