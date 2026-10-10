package nocloud

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

type fakeResolver struct {
	rec *identity.VMRecord
	err error
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, f.err
}

// fakeUserData returns fixed user-data or an error.
type fakeUserData struct {
	data string
	err  error
}

func (f *fakeUserData) UserData(_ context.Context, _ *identity.VMRecord) (string, error) {
	return f.data, f.err
}

func makeMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return mac
}

func testRecord() *identity.VMRecord {
	return &identity.VMRecord{
		Node:     "pve-node1",
		VMID:     100,
		NetIndex: 0,
		IfIndex:  3,
		Config: &vmconfig.VMConfig{
			Name:        "talos-worker-1",
			Description: "a test VM",
			SMBIOS:      map[string]string{"uuid": "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81"},
			Networks: map[int]vmconfig.NetworkDevice{
				0: {Model: "virtio", MAC: makeMAC("BC:24:11:24:57:C8"), Bridge: "vmbr0"},
				1: {Model: "virtio", MAC: makeMAC("52:54:00:ab:cd:ef"), Bridge: "vmbr1", MTU: 9000},
			},
		},
	}
}

func getWith(t *testing.T, rec *identity.VMRecord, ud imds.UserDataProvider, path string) (*http.Response, string) {
	t.Helper()
	handler := NewServer(ud).NewHandler(&fakeResolver{rec: rec}, "tap100i0", 3)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func get(t *testing.T, rec *identity.VMRecord, path string) (*http.Response, string) {
	t.Helper()
	return getWith(t, rec, &fakeUserData{err: imds.ErrNoUserData}, path)
}

func TestListingWithAndWithoutSlash(t *testing.T) {
	for _, path := range []string{"/nocloud", "/nocloud/"} {
		resp, body := get(t, testRecord(), path)
		assert.Equal(t, http.StatusOK, resp.StatusCode, path)
		assert.Equal(t, fileListing, body, path)
	}
}

func TestFilesWithTrailingSlash(t *testing.T) {
	// Some clients join the seed URL and file name with an extra slash.
	resp, body := get(t, testRecord(), "/nocloud/meta-data/")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, "instance-id:")
}

func TestPrefixMustBeWholeSegment(t *testing.T) {
	for _, path := range []string{"/nocloudmeta-data", "/nocloud-net/meta-data", "/openstack", "/"} {
		resp, _ := get(t, testRecord(), path)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
	}
}

func TestUnknownFile(t *testing.T) {
	for _, path := range []string{"/nocloud/foo", "/nocloud/meta-data/x", "/nocloud/latest/meta-data"} {
		resp, _ := get(t, testRecord(), path)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, path)
	}
}

func TestIdentityLookupFailure(t *testing.T) {
	handler := NewServer(&fakeUserData{}).NewHandler(&fakeResolver{err: identity.ErrNotFound}, "tap100i0", 3)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nocloud/meta-data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestMetaData(t *testing.T) {
	resp, body := get(t, testRecord(), "/nocloud/meta-data")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "instance-id: 2c8c7c76-a26c-4eb7-b04c-bf52bc095b81\nlocal-hostname: talos-worker-1\n", body)

	var md map[string]string
	require.NoError(t, yaml.Unmarshal([]byte(body), &md))
	assert.Equal(t, map[string]string{
		"instance-id":    "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81",
		"local-hostname": "talos-worker-1",
	}, md)
}

func TestMetaDataUUIDFallback(t *testing.T) {
	rec := testRecord()
	rec.Config.SMBIOS = nil
	_, body := get(t, rec, "/nocloud/meta-data")

	var md map[string]string
	require.NoError(t, yaml.Unmarshal([]byte(body), &md))
	assert.Equal(t, "100", md["instance-id"])
}

func TestUserDataPresent(t *testing.T) {
	resp, body := getWith(t, testRecord(), &fakeUserData{data: "version: v1alpha1\n---\nkind: X"}, "/nocloud/user-data")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "version: v1alpha1\n---\nkind: X", body)
}

func TestUserDataAbsentIsEmpty200(t *testing.T) {
	resp, body := get(t, testRecord(), "/nocloud/user-data")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body)
}

func TestUserDataUnavailableIs503(t *testing.T) {
	ud := &fakeUserData{data: "partial", err: errors.Join(imds.ErrUserDataUnavailable, errors.New("x"))}
	resp, body := getWith(t, testRecord(), ud, "/nocloud/user-data")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
	assert.NotContains(t, body, "partial")
}

func TestVendorDataEmpty(t *testing.T) {
	resp, body := get(t, testRecord(), "/nocloud/vendor-data")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, body)
}

func TestNetworkConfigDefaultDHCP(t *testing.T) {
	resp, body := get(t, testRecord(), "/nocloud/network-config")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `version: 2
ethernets:
  net0:
    match:
      macaddress: "bc:24:11:24:57:c8"
    dhcp4: true
  net1:
    match:
      macaddress: "52:54:00:ab:cd:ef"
    dhcp4: true
    mtu: 9000
`, body)
}

func TestNetworkConfigDefaultMTUInheritOmitted(t *testing.T) {
	rec := testRecord()
	nic := rec.Config.Networks[1]
	nic.MTU = 1 // Proxmox: inherit the bridge MTU
	rec.Config.Networks[1] = nic
	_, body := get(t, rec, "/nocloud/network-config")
	assert.NotContains(t, body, "mtu")
}

func TestNetworkConfigDefaultNoNICs(t *testing.T) {
	rec := testRecord()
	rec.Config.Networks = map[int]vmconfig.NetworkDevice{}
	resp, body := get(t, rec, "/nocloud/network-config")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "version: 2\nethernets: {}\n", body)
}

func TestNetworkConfigFromNotesVerbatim(t *testing.T) {
	cases := map[string]string{
		"v2 wrapped static": `network:
  version: 2
  ethernets:
    net0:
      match:
        macaddress: "bc:24:11:24:57:c8"
      addresses:
        - 192.168.1.10/24
        - 2001:db8::10/64
      routes:
        - to: 0.0.0.0/0
          via: 192.168.1.1
        - to: ::/0
          via: 2001:db8::1
      nameservers:
        addresses: [192.168.1.1]`,
		"v2 bare dhcp6": `version: 2
ethernets:
  net0:
    match:
      macaddress: "bc:24:11:24:57:c8"
    dhcp4: true
    dhcp6: true`,
		"v1 static": `version: 1
config:
  - type: physical
    name: eth0
    mac_address: "bc:24:11:24:57:c8"
    subnets:
      - type: static
        address: 192.168.1.10/24
        gateway: 192.168.1.1
      - type: static6
        address: 2001:db8::10/64
        gateway: 2001:db8::1`,
	}
	for name, nc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := testRecord()
			rec.Config.Description = "notes\n<!--#user-data\nmachine: {}\n-->\n<!--#network-config\n" + nc + "\n-->"
			resp, body := get(t, rec, "/nocloud/network-config")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, nc+"\n", body)
		})
	}
}

func TestNetworkConfigInvalidNotesFallsBack(t *testing.T) {
	for name, nc := range map[string]string{
		"bad yaml":     "network: [",
		"no version":   "network:\n  ethernets: {}",
		"version 3":    "version: 3",
		"string vers":  "version: \"2\"",
		"not a map":    "- a\n- b",
		"scalar":       "hello",
		"network null": "network:",
	} {
		t.Run(name, func(t *testing.T) {
			rec := testRecord()
			rec.Config.Description = "<!--#network-config\n" + nc + "\n-->"
			resp, body := get(t, rec, "/nocloud/network-config")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Contains(t, body, "dhcp4: true")
		})
	}
}
