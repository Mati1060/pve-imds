// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package userdata

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/pvepool"
	"github.com/wyattanderson/pve-imds/internal/secrets"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

const workerTemplate = "<!--#user-data secrets=worker\n" +
	"version: v1alpha1\n" +
	"machine:\n" +
	"  token: {{ secret \"machine_token\" }}\n" +
	"cluster:\n" +
	"  secret: {{ secret \"cluster_secret\" }}\n" +
	"---\n" +
	"kind: HostnameConfig\n" +
	"-->"

const workerRendered = "version: v1alpha1\n" +
	"machine:\n" +
	"  token: TOKVALUE1\n" +
	"cluster:\n" +
	"  secret: SECVALUE2\n" +
	"---\n" +
	"kind: HostnameConfig"

// fakeSource returns sets keyed by "pool/set" (or "tag:name/set" for tag
// scopes) and records calls.
type fakeSource struct {
	sets  map[string]map[string]string
	err   error
	calls []string
}

func (f *fakeSource) Get(_ context.Context, scope secrets.Scope, set string) (map[string]string, error) {
	key := scope.Name + "/" + set
	if scope.Kind == secrets.ScopeTag {
		key = "tag:" + key
	}
	f.calls = append(f.calls, key)
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.sets[key]
	if !ok {
		return nil, secrets.ErrSetNotFound
	}
	return v, nil
}

func record(desc string) *identity.VMRecord {
	return &identity.VMRecord{VMID: 100, Config: &vmconfig.VMConfig{Description: desc}}
}

type env struct {
	provider *Provider
	source   *fakeSource
	fs       afero.Fs
	logs     *bytes.Buffer
}

func newEnv(t *testing.T, userCfg string) *env {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, pvepool.DefaultUserCfgPath, []byte(userCfg), 0o640))
	src := &fakeSource{sets: map[string]map[string]string{
		"k8s-dmz-01/worker": {"machine_token": "TOKVALUE1", "cluster_secret": "SECVALUE2"},
		"other/worker":      {"machine_token": "OTHER", "cluster_secret": "OTHER"},
	}}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	return &env{
		provider: New(log, src, PoolScope{Pools: pvepool.New(fs, pvepool.DefaultUserCfgPath)}),
		source:   src,
		fs:       fs,
		logs:     logs,
	}
}

func assertUnavailable(t *testing.T, out string, err error) {
	t.Helper()
	require.ErrorIs(t, err, imds.ErrUserDataUnavailable)
	assert.Empty(t, out)
}

func TestNoUserData(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	_, err := e.provider.UserData(context.Background(), record("plain notes"))
	assert.ErrorIs(t, err, imds.ErrNoUserData)
}

func TestPlainUserDataUnchanged(t *testing.T) {
	// Without secrets= nothing is processed, not even placeholders, and no
	// pool or secret lookup happens.
	e := newEnv(t, "")
	desc := "<!--#user-data\n#cloud-config\nruncmd: [echo '{{ secret \"x\" }}', '{{ ds.meta_data.name }}']\n-->"
	out, err := e.provider.UserData(context.Background(), record(desc))
	require.NoError(t, err)
	assert.Equal(t, "#cloud-config\nruncmd: [echo '{{ secret \"x\" }}', '{{ ds.meta_data.name }}']", out)
	assert.Empty(t, e.source.calls)
}

func TestPlainUserDataWithSecretsDisabled(t *testing.T) {
	p := New(slog.New(slog.DiscardHandler), nil, nil)
	out, err := p.UserData(context.Background(), record("<!--#user-data\n#cloud-config\n-->"))
	require.NoError(t, err)
	assert.Equal(t, "#cloud-config", out)
}

func TestTemplatedUserData(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100,101:\n")
	out, err := e.provider.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)
	assert.Equal(t, workerRendered, out)
	assert.Equal(t, []string{"k8s-dmz-01/worker"}, e.source.calls)
}

func TestTemplatedNestedPool(t *testing.T) {
	e := newEnv(t, "pool:dc1/k8s::100:\n")
	e.source.sets["dc1/k8s/worker"] = map[string]string{"machine_token": "n", "cluster_secret": "n"}
	_, err := e.provider.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)
	assert.Equal(t, []string{"dc1/k8s/worker"}, e.source.calls)
}

func TestTemplatedSecretsDisabled(t *testing.T) {
	p := New(slog.New(slog.DiscardHandler), nil, nil)
	out, err := p.UserData(context.Background(), record(workerTemplate))
	assertUnavailable(t, out, err)
}

func TestTemplatedNotInPool(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::101:\n")
	out, err := e.provider.UserData(context.Background(), record(workerTemplate))
	assertUnavailable(t, out, err)
	assert.Empty(t, e.source.calls)
	assert.Contains(t, e.logs.String(), "outcome=vm_not_in_pool")
}

func TestTemplatedPoolLookupFails(t *testing.T) {
	e := newEnv(t, "")
	require.NoError(t, e.fs.Remove(pvepool.DefaultUserCfgPath))
	out, err := e.provider.UserData(context.Background(), record(workerTemplate))
	assertUnavailable(t, out, err)
}

func TestTemplatedInvalidSetName(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	for _, set := range []string{"", "../other/worker", "..", "other/worker", "a.b"} {
		desc := "<!--#user-data secrets=" + set + "\nmachine: {{ secret \"machine_token\" }}\n-->"
		out, err := e.provider.UserData(context.Background(), record(desc))
		assertUnavailable(t, out, err)
	}
	assert.Empty(t, e.source.calls, "invalid set names must never reach the secret source")
}

func TestTemplatedCannotReachOtherPool(t *testing.T) {
	// The VM is in k8s-dmz-01; whatever its Notes say, only that pool is
	// ever queried.
	e := newEnv(t, "pool:k8s-dmz-01::100:\npool:other:::\n")
	for _, set := range []string{"worker", "../other/worker", "other"} {
		desc := "<!--#user-data secrets=" + set + "\nmachine: {{ secret \"machine_token\" }}\n-->"
		out, _ := e.provider.UserData(context.Background(), record(desc))
		assert.NotContains(t, out, "OTHER")
	}
	for _, c := range e.source.calls {
		assert.Regexp(t, `^k8s-dmz-01/`, c)
	}
}

func TestTemplatedMissingSet(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	desc := "<!--#user-data secrets=nope\nmachine: {{ secret \"machine_token\" }}\n-->"
	out, err := e.provider.UserData(context.Background(), record(desc))
	assertUnavailable(t, out, err)
}

func TestTemplatedMissingField(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	desc := "<!--#user-data secrets=worker\na: {{ secret \"machine_token\" }}\nb: {{ secret \"nope\" }}\n-->"
	out, err := e.provider.UserData(context.Background(), record(desc))
	assertUnavailable(t, out, err)
}

func TestTemplatedSourceError(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	e.source.err = errors.New("connection refused")
	out, err := e.provider.UserData(context.Background(), record(workerTemplate))
	assertUnavailable(t, out, err)
}

func TestTemplatedPoolChangeTakesEffect(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	_, err := e.provider.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)

	require.NoError(t, afero.WriteFile(e.fs, pvepool.DefaultUserCfgPath, []byte("pool:other::100:\n"), 0o640))
	out, err := e.provider.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)
	assert.Contains(t, out, "OTHER")
	assert.Equal(t, []string{"k8s-dmz-01/worker", "other/worker"}, e.source.calls)
}

func TestLogsContainNoContent(t *testing.T) {
	e := newEnv(t, "pool:k8s-dmz-01::100:\n")
	_, err := e.provider.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)
	desc := "<!--#user-data secrets=worker\na: {{ secret \"machine_token\" }}\nb: {{ secret \"nope\" }}\n-->"
	_, _ = e.provider.UserData(context.Background(), record(desc))

	logs := e.logs.String()
	assert.Contains(t, logs, "vmid=100")
	assert.Contains(t, logs, "pool=k8s-dmz-01")
	assert.Contains(t, logs, "set=worker")
	for _, secret := range []string{"TOKVALUE1", "SECVALUE2", "version: v1alpha1", "HostnameConfig"} {
		assert.NotContains(t, logs, secret)
	}
}

// TestOpenBaoErrors drives the real KV client against a fake TLS server and
// checks that every failure mode is reported as unavailable (→ 503).
func TestOpenBaoErrors(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"forbidden": func(w http.ResponseWriter) {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		},
		"not found": func(w http.ResponseWriter) {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		},
		"sealed": func(w http.ResponseWriter) {
			http.Error(w, `{"errors":["Vault is sealed"]}`, http.StatusServiceUnavailable)
		},
		"garbage": func(w http.ResponseWriter) {
			fmt.Fprint(w, "not json") //nolint:errcheck
		},
		"unreachable": nil,
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				respond(w)
			}))
			defer srv.Close()

			p := providerFor(t, srv, "pool:k8s-dmz-01::100:\n")
			if respond == nil {
				srv.Close()
			}
			out, err := p.UserData(context.Background(), record(workerTemplate))
			assertUnavailable(t, out, err)
		})
	}
}

func TestOpenBaoSuccess(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/data/pve-imds/pools/k8s-dmz-01/worker" || r.Header.Get("X-Vault-Token") != "tok" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"machine_token":"TOKVALUE1","cluster_secret":"SECVALUE2"}}}`) //nolint:errcheck
	}))
	defer srv.Close()

	p := providerFor(t, srv, "pool:k8s-dmz-01::100:\n")
	out, err := p.UserData(context.Background(), record(workerTemplate))
	require.NoError(t, err)
	assert.Equal(t, workerRendered, out)
}

// providerFor builds a Provider wired to srv through the production KV
// client and cache.
func providerFor(t *testing.T, srv *httptest.Server, userCfg string) *Provider {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

	kv, err := secrets.NewKVv2(secrets.KVOptions{
		Address:      srv.URL,
		CAFile:       caFile,
		TokenFile:    tokenFile,
		PathTemplate: "kv/data/pve-imds/pools/{pool}/{name}",
	})
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, pvepool.DefaultUserCfgPath, []byte(userCfg), 0o640))
	return New(slog.New(slog.DiscardHandler), secrets.NewCache(kv, time.Minute), PoolScope{Pools: pvepool.New(fs, pvepool.DefaultUserCfgPath)})
}

// ---------------------------------------------------------------------------
// Tag scope
// ---------------------------------------------------------------------------

// fakeRegistry reports the listed tags as registered.
type fakeRegistry map[string]bool

func (f fakeRegistry) IsRegistered(tag string) (bool, error) { return f[tag], nil }

func tagProvider(t *testing.T, registry TagRegistry) (*Provider, *fakeSource, *bytes.Buffer) {
	t.Helper()
	src := &fakeSource{sets: map[string]map[string]string{
		"tag:k8s-dmz-01/worker": {"machine_token": "TAGTOKEN", "cluster_secret": "TAGSECRET"},
	}}
	logs := &bytes.Buffer{}
	p := New(slog.New(slog.NewTextHandler(logs, nil)), src, TagScope{Prefix: "pve-imds-", Registry: registry})
	return p, src, logs
}

func taggedRecord(desc string, tags ...string) *identity.VMRecord {
	rec := record(desc)
	rec.Config.Tags = tags
	return rec
}

func TestTagScope(t *testing.T) {
	p, src, logs := tagProvider(t, fakeRegistry{"pve-imds-k8s-dmz-01": true})
	out, err := p.UserData(context.Background(), taggedRecord(workerTemplate, "prod", "pve-imds-k8s-dmz-01", "web"))
	require.NoError(t, err)
	assert.Contains(t, out, "token: TAGTOKEN")
	assert.Equal(t, []string{"tag:k8s-dmz-01/worker"}, src.calls)
	assert.Contains(t, logs.String(), "tag=k8s-dmz-01")
}

func TestTagScopeCaseInsensitive(t *testing.T) {
	p, src, _ := tagProvider(t, nil)
	_, err := p.UserData(context.Background(), taggedRecord(workerTemplate, "PVE-IMDS-K8S-DMZ-01"))
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:k8s-dmz-01/worker"}, src.calls)
}

func TestTagScopeFailures(t *testing.T) {
	cases := map[string]struct {
		tags     []string
		registry TagRegistry
		outcome  string
	}{
		"no tags":          {nil, nil, "no_scope_tag"},
		"no matching tag":  {[]string{"prod", "k8s-dmz-01"}, nil, "no_scope_tag"},
		"bare prefix":      {[]string{"pve-imds-"}, nil, "no_scope_tag"},
		"two scope tags":   {[]string{"pve-imds-a", "pve-imds-b"}, nil, "multiple_scope_tags"},
		"not registered":   {[]string{"pve-imds-k8s-dmz-01"}, fakeRegistry{}, "tag_not_registered"},
		"other registered": {[]string{"pve-imds-k8s-dmz-01"}, fakeRegistry{"pve-imds-other": true}, "tag_not_registered"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, src, logs := tagProvider(t, tc.registry)
			out, err := p.UserData(context.Background(), taggedRecord(workerTemplate, tc.tags...))
			assertUnavailable(t, out, err)
			assert.Empty(t, src.calls)
			assert.Contains(t, logs.String(), "outcome="+tc.outcome)
		})
	}
}

func TestTagScopeDuplicateTagIsOneScope(t *testing.T) {
	p, src, _ := tagProvider(t, nil)
	_, err := p.UserData(context.Background(), taggedRecord(workerTemplate, "pve-imds-k8s-dmz-01", "PVE-IMDS-K8S-DMZ-01"))
	require.NoError(t, err)
	assert.Len(t, src.calls, 1)
}

func TestTagScopeIgnoresNotes(t *testing.T) {
	// The scope comes only from the VM's tags; the set name cannot escape it.
	p, src, _ := tagProvider(t, nil)
	for _, set := range []string{"worker", "../other/worker", "..%2Fother"} {
		desc := "<!--#user-data secrets=" + set + "\nmachine: {{ secret \"machine_token\" }}\n-->"
		_, _ = p.UserData(context.Background(), taggedRecord(desc, "pve-imds-k8s-dmz-01"))
	}
	for _, c := range src.calls {
		assert.Regexp(t, `^tag:k8s-dmz-01/`, c)
	}
}

func TestTagScopeEndToEnd(t *testing.T) {
	// Real KV client with a {tag} template and a real datacenter.cfg registry.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/data/pve-imds/tags/k8s-dmz-01/worker" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"data":{"data":{"machine_token":"TOKVALUE1","cluster_secret":"SECVALUE2"}}}`) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok"), 0o600))

	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/pve/datacenter.cfg", []byte("registered-tags: pve-imds-k8s-dmz-01\n"), 0o640))

	cfg := config.Default().Secrets
	cfg.Enabled = true
	cfg.Address = srv.URL
	cfg.CAFile = caFile
	cfg.TokenFile = tokenFile
	cfg.PathTemplate = "kv/data/pve-imds/tags/{tag}/{name}"

	p, err := FromConfig(cfg, fs, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	out, err := p.UserData(context.Background(), taggedRecord(workerTemplate, "pve-imds-k8s-dmz-01"))
	require.NoError(t, err)
	assert.Equal(t, workerRendered, out)

	// Unregistering the tag takes effect on the next request.
	require.NoError(t, afero.WriteFile(fs, "/etc/pve/datacenter.cfg", []byte("keyboard: en-us\n"), 0o640))
	out, err = p.UserData(context.Background(), taggedRecord(workerTemplate, "pve-imds-k8s-dmz-01"))
	assertUnavailable(t, out, err)

	// With the check turned off, an unregistered tag is accepted.
	cfg.RequireRegisteredTags = false
	p, err = FromConfig(cfg, fs, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	_, err = p.UserData(context.Background(), taggedRecord(workerTemplate, "pve-imds-k8s-dmz-01"))
	require.NoError(t, err)
}

func TestFromConfig(t *testing.T) {
	def := config.Default().Secrets

	p, err := FromConfig(def, afero.NewMemMapFs(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.Nil(t, p.source, "secrets are disabled by default")

	cfg := def
	cfg.Enabled = true
	_, err = FromConfig(cfg, afero.NewMemMapFs(), slog.New(slog.DiscardHandler))
	require.Error(t, err, "enabled without address/token_file must fail at startup")

	cfg.Address = "https://bao.example.com:8200"
	cfg.TokenFile = "/run/openbao-agent/token"
	p, err = FromConfig(cfg, afero.NewMemMapFs(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.NotNil(t, p.source)
	assert.IsType(t, PoolScope{}, p.scopes)

	cfg.PathTemplate = "kv/data/pve-imds/tags/{tag}/{name}"
	p, err = FromConfig(cfg, afero.NewMemMapFs(), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	assert.IsType(t, TagScope{}, p.scopes)
	assert.NotNil(t, p.scopes.(TagScope).Registry, "registered tags are required by default")

	cfg.TagPrefix = ""
	_, err = FromConfig(cfg, afero.NewMemMapFs(), slog.New(slog.DiscardHandler))
	require.Error(t, err, "an empty tag prefix must be rejected")
}
