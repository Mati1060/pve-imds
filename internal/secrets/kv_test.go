// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeKV is a minimal OpenBao KV v2 server over TLS.
type fakeKV struct {
	srv *httptest.Server

	mu       sync.Mutex
	token    string
	sets     map[string]string // API path → JSON "data" object
	status   int               // if non-zero, returned for every request
	requests []*http.Request
}

func newFakeKV(t *testing.T) *fakeKV {
	t.Helper()
	f := &fakeKV{token: "tok-1", sets: map[string]string{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKV) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	data, ok := f.sets[r.URL.Path]
	if !ok {
		http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		return
	}
	fmt.Fprintf(w, `{"data":{"data":%s,"metadata":{"version":1}}}`, data) //nolint:errcheck
}

func (f *fakeKV) lastRequest() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

// kvClient writes the CA and token files and returns a KVv2 pointed at f.
func kvClient(t *testing.T, f *fakeKV, mod func(*KVOptions)) (*KVv2, string) {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte(f.token+"\n"), 0o600))

	opts := KVOptions{
		Address:      f.srv.URL,
		CAFile:       caFile,
		TokenFile:    tokenFile,
		PathTemplate: defaultTmpl,
	}
	if mod != nil {
		mod(&opts)
	}
	kv, err := NewKVv2(opts)
	require.NoError(t, err)
	return kv, tokenFile
}

func TestKVGet(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/k8s-dmz-01/worker"] = `{"token":"abc","ca":"PEM","n":5,"b":true,"o":{"x":1}}`
	kv, _ := kvClient(t, f, nil)

	vals, err := kv.Get(context.Background(), pool("k8s-dmz-01"), "worker")
	require.NoError(t, err)
	// Non-string fields are dropped.
	assert.Equal(t, map[string]string{"token": "abc", "ca": "PEM"}, vals)

	req := f.lastRequest()
	assert.Equal(t, "tok-1", req.Header.Get("X-Vault-Token"))
	assert.Empty(t, req.Header.Get("X-Vault-Namespace"))
}

func TestKVGetNestedPool(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/dc1/k8s/worker"] = `{"token":"nested"}`
	kv, _ := kvClient(t, f, nil)

	vals, err := kv.Get(context.Background(), pool("dc1/k8s"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "nested", vals["token"])
}

func TestKVGetTagScope(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/tags/k8s-dmz-01/worker"] = `{"token":"by-tag"}`
	kv, _ := kvClient(t, f, func(o *KVOptions) { o.PathTemplate = tagTmpl })
	assert.Equal(t, ScopeTag, kv.ScopeKind())

	vals, err := kv.Get(context.Background(), tag("k8s-dmz-01"), "worker")
	require.NoError(t, err)
	assert.Equal(t, "by-tag", vals["token"])

	// A pool scope cannot be used with a tag template.
	_, err = kv.Get(context.Background(), pool("k8s-dmz-01"), "worker")
	assert.ErrorIs(t, err, ErrInvalidScope)
}

func TestKVGetNamespaceHeader(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/p/s"] = `{"k":"v"}`
	kv, _ := kvClient(t, f, func(o *KVOptions) { o.Namespace = "pve-cluster-a" })

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.NoError(t, err)
	assert.Equal(t, "pve-cluster-a", f.lastRequest().Header.Get("X-Vault-Namespace"))
}

func TestKVGetNotFound(t *testing.T) {
	f := newFakeKV(t)
	kv, _ := kvClient(t, f, nil)

	_, err := kv.Get(context.Background(), pool("p"), "missing")
	assert.ErrorIs(t, err, ErrSetNotFound)
}

func TestKVGetDeletedVersion(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/p/s"] = `null`
	kv, _ := kvClient(t, f, nil)

	_, err := kv.Get(context.Background(), pool("p"), "s")
	assert.ErrorIs(t, err, ErrSetNotFound)
}

func TestKVGetForbidden(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/p/s"] = `{"k":"v"}`
	kv, tokenFile := kvClient(t, f, nil)
	require.NoError(t, os.WriteFile(tokenFile, []byte("wrong"), 0o600))

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrSetNotFound)
	assert.Contains(t, err.Error(), "403")
}

func TestKVGetServerError(t *testing.T) {
	f := newFakeKV(t)
	f.status = http.StatusServiceUnavailable // e.g. sealed
	kv, _ := kvClient(t, f, nil)

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
}

func TestKVGetUnreachable(t *testing.T) {
	f := newFakeKV(t)
	kv, _ := kvClient(t, f, nil)
	f.srv.Close()

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)
}

func TestKVGetUntrustedCertificate(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/p/s"] = `{"k":"v"}`
	// No CA file: the test server's self-signed certificate is not trusted.
	kv, _ := kvClient(t, f, func(o *KVOptions) { o.CAFile = "" })

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)
}

func TestKVGetTokenRereadOnChange(t *testing.T) {
	f := newFakeKV(t)
	f.sets["/v1/kv/data/pve-imds/pools/p/s"] = `{"k":"v"}`
	kv, tokenFile := kvClient(t, f, nil)

	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.NoError(t, err)

	// The agent rotates the token; the next request uses the new one.
	f.mu.Lock()
	f.token = "tok-2"
	f.mu.Unlock()
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok-2"), 0o600))

	_, err = kv.Get(context.Background(), pool("p"), "s")
	require.NoError(t, err)
	assert.Equal(t, "tok-2", f.lastRequest().Header.Get("X-Vault-Token"))
}

func TestKVGetTokenFileMissingOrEmpty(t *testing.T) {
	f := newFakeKV(t)
	kv, tokenFile := kvClient(t, f, nil)

	require.NoError(t, os.WriteFile(tokenFile, []byte("  \n"), 0o600))
	_, err := kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)

	require.NoError(t, os.Remove(tokenFile))
	_, err = kv.Get(context.Background(), pool("p"), "s")
	require.Error(t, err)
}

func TestKVGetRejectsInvalidInput(t *testing.T) {
	f := newFakeKV(t)
	kv, _ := kvClient(t, f, nil)

	_, err := kv.Get(context.Background(), pool("p"), "../q/s")
	require.ErrorIs(t, err, ErrInvalidSetName)
	_, err = kv.Get(context.Background(), pool("p/.."), "s")
	require.ErrorIs(t, err, ErrInvalidScope)
	assert.Empty(t, f.requests, "no request must be sent for invalid input")
}

func TestNewKVv2Validation(t *testing.T) {
	base := KVOptions{Address: "https://bao:8200", TokenFile: "/t", PathTemplate: defaultTmpl}

	_, err := NewKVv2(base)
	require.NoError(t, err)

	o := base
	o.Address = "http://bao:8200"
	_, err = NewKVv2(o)
	assert.Error(t, err, "plain http must be rejected")

	o = base
	o.TokenFile = ""
	_, err = NewKVv2(o)
	assert.Error(t, err)

	o = base
	o.PathTemplate = "kv/data/{name}"
	_, err = NewKVv2(o)
	assert.Error(t, err)

	o = base
	o.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	_, err = NewKVv2(o)
	assert.Error(t, err)
}
