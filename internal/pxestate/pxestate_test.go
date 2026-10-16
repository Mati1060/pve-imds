// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package pxestate

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/secrets"
)

const testUUID = "86f5aa5e-08a3-40cb-a642-efad20b5b061"

const testPath = "/v1/kv/data/pve-imds/pxe/" + testUUID

// fakeKV is a minimal OpenBao KV v2 server over TLS.
type fakeKV struct {
	srv *httptest.Server

	mu      sync.Mutex
	token   string
	entries map[string]string // API path → raw JSON response body
	writes  map[string]map[string]string
	status  int           // if non-zero, returned for every request
	delay   time.Duration // if non-zero, slept before answering
	reqs    []*http.Request
}

func newFakeKV(t *testing.T) *fakeKV {
	t.Helper()
	f := &fakeKV{token: "tok-1", entries: map[string]string{}, writes: map[string]map[string]string{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeKV) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	delay := f.delay
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		body, ok := f.entries[r.URL.Path]
		if !ok {
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
			return
		}
		io.WriteString(w, body) //nolint:errcheck
	case http.MethodPost:
		var req struct {
			Data map[string]string `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.writes[r.URL.Path] = req.Data
		io.WriteString(w, `{"data":{"version":1}}`) //nolint:errcheck
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeKV) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs
}

func newStore(t *testing.T, f *fakeKV, timeout time.Duration) *Store {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	tokenFile := filepath.Join(dir, "token")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte(f.token+"\n"), 0o600))

	kv, err := secrets.NewKVClient(secrets.ConnOptions{
		Address:   f.srv.URL,
		Namespace: "ns1",
		CAFile:    caFile,
		TokenFile: tokenFile,
		Timeout:   timeout,
	})
	require.NoError(t, err)
	s, err := New(kv, DefaultPathTemplate)
	require.NoError(t, err)
	return s
}

func TestGet(t *testing.T) {
	cases := []struct {
		name      string
		body      string // response for testPath; empty means 404
		status    int
		delay     time.Duration
		want      Record
		wantFound bool
		wantErr   string
	}{
		{
			name: "found",
			body: `{"data":{"data":{"image":"debian13","version":"2026.10.01","sha256":"ab12","provisioned_at":"2026-10-13T18:00:00Z","method":"disk"},"metadata":{"version":3}}}`,
			want: Record{
				Image:         "debian13",
				Version:       "2026.10.01",
				SHA256:        "ab12",
				ProvisionedAt: time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC),
				Method:        "disk",
			},
			wantFound: true,
		},
		{
			name:      "found with missing fields",
			body:      `{"data":{"data":{"image":"debian13"}}}`,
			want:      Record{Image: "debian13"},
			wantFound: true,
		},
		{
			name: "not found",
		},
		{
			name: "deleted latest version",
			body: `{"data":{"data":null,"metadata":{"deletion_time":"2026-10-13T18:00:00Z"}}}`,
		},
		{
			name:    "forbidden",
			status:  http.StatusForbidden,
			wantErr: "403",
		},
		{
			name:    "server error",
			status:  http.StatusInternalServerError,
			wantErr: "500",
		},
		{
			name:    "timeout",
			body:    `{"data":{"data":{"image":"debian13"}}}`,
			delay:   2 * time.Second,
			wantErr: "request failed",
		},
		{
			name:    "malformed json",
			body:    `{"data":`,
			wantErr: "decode response",
		},
		{
			name:    "non-string field",
			body:    `{"data":{"data":{"image":13}}}`,
			wantErr: "not a string",
		},
		{
			name:    "bad timestamp",
			body:    `{"data":{"data":{"image":"debian13","provisioned_at":"yesterday"}}}`,
			wantErr: "provisioned_at",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeKV(t)
			if tc.body != "" {
				f.entries[testPath] = tc.body
			}
			f.status = tc.status
			f.delay = tc.delay
			s := newStore(t, f, 100*time.Millisecond)

			// Upper case must be normalized to the lowercase key.
			rec, found, err := s.Get(context.Background(), "86F5AA5E-08A3-40CB-A642-EFAD20B5B061")
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.False(t, found)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, tc.want, rec)

			req := f.requests()[0]
			assert.Equal(t, testPath, req.URL.Path)
			assert.Equal(t, "tok-1", req.Header.Get("X-Vault-Token"))
			assert.Equal(t, "ns1", req.Header.Get("X-Vault-Namespace"))
		})
	}
}

func TestGetIsNotCached(t *testing.T) {
	f := newFakeKV(t)
	s := newStore(t, f, 0)

	_, found, err := s.Get(context.Background(), testUUID)
	require.NoError(t, err)
	assert.False(t, found)

	f.mu.Lock()
	f.entries[testPath] = `{"data":{"data":{"image":"debian13"}}}`
	f.mu.Unlock()

	rec, found, err := s.Get(context.Background(), testUUID)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "debian13", rec.Image)
	assert.Len(t, f.requests(), 2)
}

func TestPut(t *testing.T) {
	f := newFakeKV(t)
	s := newStore(t, f, 0)

	at := time.Date(2026, 10, 13, 20, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	err := s.Put(context.Background(), testUUID, Record{
		Image:         "debian13",
		Version:       "2026.10.01",
		SHA256:        "ab12",
		ProvisionedAt: at,
		Method:        "chain",
	})
	require.NoError(t, err)

	assert.Equal(t, map[string]string{
		"image":          "debian13",
		"version":        "2026.10.01",
		"sha256":         "ab12",
		"provisioned_at": "2026-10-13T18:00:00Z",
		"method":         "chain",
	}, f.writes[testPath])
	req := f.requests()[0]
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "ns1", req.Header.Get("X-Vault-Namespace"))
}

func TestPutRoundTrip(t *testing.T) {
	f := newFakeKV(t)
	s := newStore(t, f, 0)
	want := Record{Image: "debian13", Version: "v1", SHA256: "x", ProvisionedAt: time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC), Method: "disk"}
	require.NoError(t, s.Put(context.Background(), testUUID, want))

	data, err := json.Marshal(map[string]any{"data": map[string]any{"data": f.writes[testPath]}})
	require.NoError(t, err)
	f.entries[testPath] = string(data)

	got, found, err := s.Get(context.Background(), testUUID)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, want, got)
}

func TestPutErrors(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		f := newFakeKV(t)
		f.status = status
		s := newStore(t, f, 0)
		err := s.Put(context.Background(), testUUID, Record{Image: "debian13"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), http.StatusText(status))
	}
}

func TestInvalidUUIDSendsNoRequest(t *testing.T) {
	f := newFakeKV(t)
	s := newStore(t, f, 0)

	for _, uuid := range []string{"", "500", "../x", "86f5aa5e-08a3-40cb-a642-efad20b5b06", "00000000-0000-0000-0000-000000000000"} {
		_, _, err := s.Get(context.Background(), uuid)
		require.ErrorIs(t, err, ErrInvalidUUID, uuid)
		require.ErrorIs(t, s.Put(context.Background(), uuid, Record{}), ErrInvalidUUID, uuid)
	}
	assert.Empty(t, f.requests())
}

func TestValidatePathTemplate(t *testing.T) {
	require.NoError(t, ValidatePathTemplate(DefaultPathTemplate))
	require.NoError(t, ValidatePathTemplate("secret/data/pxe/{uuid}/state"))
	require.Error(t, ValidatePathTemplate("kv/data/pve-imds/pxe"))
	require.Error(t, ValidatePathTemplate("kv/data/{pool}/{uuid}"))
}
