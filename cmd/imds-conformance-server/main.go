// Command imds-conformance-server is a test harness for the IMDS conformance
// suites. It serves either an EC2-compatible or OpenStack-compatible IMDS over
// a random TCP port using a hard-coded fake VM identity so that the Python
// conformance tests can drive cloud-init's DataSource* implementations against
// our real handlers without any Proxmox infrastructure.
//
// On startup it prints a single "ready {json}" line to stdout (then flushes)
// so the test runner knows which port to connect to and what data to expect.
//
// Flags:
//
//	-emulate ec2|openstack|nocloud   (default: ec2)
//
// In nocloud mode the fake VM has templated user-data (secrets=web) and is in
// the nested pool "conformance/nested"; secrets are served by an in-process
// fake OpenBao KV v2 server over TLS, so the full secrets path (pool lookup,
// path building, TLS, token file, rendering) is exercised.
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/afero"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/ec2"
	"github.com/wyattanderson/pve-imds/internal/imds/nocloud"
	"github.com/wyattanderson/pve-imds/internal/imds/openstack"
	"github.com/wyattanderson/pve-imds/internal/pvepool"
	"github.com/wyattanderson/pve-imds/internal/secrets"
	"github.com/wyattanderson/pve-imds/internal/userdata"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

// Fixtures for the nocloud templating scenario.
const (
	conformancePool   = "conformance/nested"
	conformanceSet    = "web"
	conformanceToken  = "s.conformance-token"
	conformanceSecret = "hunter2"
	conformanceKVPath = "/v1/kv/data/pve-imds/pools/conformance/nested/web"

	templatedUserData = "<!--#user-data secrets=" + conformanceSet + "\n" +
		"#cloud-config\n" +
		"---\n" +
		"write_files:\n" +
		"  - path: /etc/conformance\n" +
		"    content: '{{ secret \"password\" }}'\n" +
		"-->"
	renderedUserData = "#cloud-config\n" +
		"---\n" +
		"write_files:\n" +
		"  - path: /etc/conformance\n" +
		"    content: '" + conformanceSecret + "'"
)

// fakeResolver returns a fixed VMRecord on every call, ignoring ifname and
// ifindex. This lets the conformance tests exercise the HTTP handler layer
// without a running Proxmox host.
type fakeResolver struct {
	rec *identity.VMRecord
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, nil
}

// testRecord returns the fixed VM identity the harness always serves.
// The values here are the ground truth that the Python conformance tests
// assert against.
func testRecord() *identity.VMRecord {
	mac, err := net.ParseMAC("52:54:00:12:34:56")
	if err != nil {
		panic(err)
	}
	return &identity.VMRecord{
		Node:     "pve-conformance",
		VMID:     100,
		NetIndex: 0,
		IfIndex:  3,
		Config: &vmconfig.VMConfig{
			Name:        "conformance-vm",
			OSType:      "l26",
			Description: "Test VM for IMDS conformance",
			Tags:        []string{"conformance"},
			Networks: map[int]vmconfig.NetworkDevice{
				0: {
					Model:  "virtio",
					MAC:    mac,
					Bridge: "vmbr0",
				},
			},
			Raw: map[string]string{
				"cores":  "2",
				"memory": "2048",
			},
		},
	}
}

// serverInfo is JSON-serialised to stdout on startup.
type serverInfo struct {
	Port    int    `json:"port"`
	VMID    int    `json:"vmid"`
	Node    string `json:"node"`
	MAC     string `json:"mac"`
	VMName  string `json:"vm_name"`
	LocalIP string `json:"local_ipv4"`
	// UserData is the user-data the server is expected to serve, if any.
	UserData string `json:"user_data,omitempty"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	emulate := flag.String("emulate", "ec2", "IMDS emulation target: ec2, openstack or nocloud")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close() //nolint:errcheck

	port := ln.Addr().(*net.TCPAddr).Port
	rec := testRecord()
	resolver := &fakeResolver{rec}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var expectedUserData string

	var srv imds.Server
	switch *emulate {
	case "ec2":
		srv = ec2.NewServer(userdata.New(log, nil, nil))
	case "openstack":
		srv = openstack.NewServer(userdata.New(log, nil, nil))
	case "nocloud":
		provider, cleanup, err := templatingProvider(log)
		if err != nil {
			return err
		}
		defer cleanup()
		rec.Config.Description = templatedUserData
		expectedUserData = renderedUserData
		srv = nocloud.NewServer(provider)
	default:
		return fmt.Errorf("unknown -emulate value %q: must be ec2, openstack or nocloud", *emulate)
	}

	handler := srv.NewHandler(resolver, "tap100i0", rec.IfIndex)

	mac := rec.Config.Networks[0].MAC.String()
	info := serverInfo{
		Port:     port,
		VMID:     rec.VMID,
		Node:     rec.Node,
		MAC:      mac,
		VMName:   rec.Config.Name,
		LocalIP:  "",
		UserData: expectedUserData,
	}
	data, _ := json.Marshal(info)
	fmt.Printf("ready %s\n", data)
	// Flush stdout so the test runner's readline() does not block.
	_ = os.Stdout.Sync()

	if err := imds.Serve(ctx, ln, handler); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// templatingProvider starts a fake OpenBao KV v2 server over TLS and returns a
// user-data provider wired to it through the production KV client, cache and
// pool lookup. The returned cleanup stops the server and removes temp files.
func templatingProvider(log *slog.Logger) (*userdata.Provider, func(), error) {
	kv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != conformanceToken {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		if r.URL.Path != conformanceKVPath {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":{"data":{"password":%q},"metadata":{"version":1}}}`, conformanceSecret) //nolint:errcheck
	}))

	dir, err := os.MkdirTemp("", "imds-conformance-")
	if err != nil {
		kv.Close()
		return nil, nil, err
	}
	cleanup := func() {
		kv.Close()
		_ = os.RemoveAll(dir)
	}

	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.WriteFile(tokenFile, []byte(conformanceToken+"\n"), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}

	src, err := secrets.NewKVv2(secrets.KVOptions{
		Address:      kv.URL,
		CAFile:       caFile,
		TokenFile:    tokenFile,
		PathTemplate: "kv/data/pve-imds/pools/{pool}/{name}",
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	fs := afero.NewMemMapFs()
	userCfg := fmt.Sprintf("pool:%s::%d::\n", conformancePool, testRecord().VMID)
	if err := afero.WriteFile(fs, pvepool.DefaultUserCfgPath, []byte(userCfg), 0o640); err != nil {
		cleanup()
		return nil, nil, err
	}

	scopes := userdata.PoolScope{Pools: pvepool.New(fs, pvepool.DefaultUserCfgPath)}
	provider := userdata.New(log, secrets.NewCache(src, time.Minute), scopes)
	return provider, cleanup, nil
}
