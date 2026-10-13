package provision

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const manifestDoc = `{"images": {"debian13": {"type": "disk", "latest": "1", "versions": {
  "1": {"url": "https://rgw.example.com/1.raw.zst", "sha256": "` + sha + `", "size": 1},
  "0": {"url": "http://rgw.example.com/0.raw.zst", "sha256": "` + sha + `", "size": 1}
}}}}`

type fakeRGW struct {
	srv *httptest.Server

	mu     sync.Mutex
	body   string
	status int
	hits   int
}

func newFakeRGW(t *testing.T) *fakeRGW {
	t.Helper()
	f := &fakeRGW{body: manifestDoc}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		io.WriteString(w, f.body) //nolint:errcheck
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRGW) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func newSource(t *testing.T, f *fakeRGW, log *slog.Logger) (*HTTPManifest, *time.Time) {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600))
	src, err := NewHTTPManifest(ManifestOptions{
		URL:                  f.srv.URL + "/pxe/manifest.json",
		CAFile:               caFile,
		TTL:                  time.Minute,
		ChainAllowedPrefixes: allowed,
		Log:                  log,
	})
	require.NoError(t, err)
	now := time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	return src, &now
}

func TestHTTPManifestCachesForTTL(t *testing.T) {
	f := newFakeRGW(t)
	var logs bytes.Buffer
	src, now := newSource(t, f, slog.New(slog.NewTextHandler(&logs, nil)))
	ctx := context.Background()

	m, err := src.Manifest(ctx)
	require.NoError(t, err)
	assert.Contains(t, m.Images["debian13"].Versions, "1")
	assert.NotContains(t, m.Images["debian13"].Versions, "0")
	assert.Contains(t, logs.String(), "skipping invalid manifest entry")

	_, err = src.Manifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, f.hits, "served from cache within the TTL")

	*now = now.Add(time.Minute)
	_, err = src.Manifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, f.hits, "refetched after the TTL")
}

func TestHTTPManifestNoStaleServingAndNoErrorCaching(t *testing.T) {
	f := newFakeRGW(t)
	src, now := newSource(t, f, nil)
	ctx := context.Background()

	_, err := src.Manifest(ctx)
	require.NoError(t, err)

	// The cache expires and the server fails: no stale manifest.
	*now = now.Add(2 * time.Minute)
	f.set(http.StatusInternalServerError, "")
	_, err = src.Manifest(ctx)
	require.ErrorContains(t, err, "500")

	// The error is not cached: the next request fetches again.
	f.set(0, manifestDoc)
	_, err = src.Manifest(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, f.hits)
}

func TestHTTPManifestErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "not found", status: http.StatusNotFound, want: "404"},
		{name: "redirect", status: http.StatusFound, want: "302"},
		{name: "malformed json", body: `{"images":`, want: "decode manifest"},
		{name: "too large", body: `{"images": {}, "pad": "` + strings.Repeat("x", manifestMaxBytes) + `"}`, want: "larger than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRGW(t)
			f.set(tc.status, tc.body)
			src, _ := newSource(t, f, nil)
			_, err := src.Manifest(context.Background())
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestHTTPManifestUntrustedCertificate(t *testing.T) {
	f := newFakeRGW(t)
	src, err := NewHTTPManifest(ManifestOptions{URL: f.srv.URL, TTL: time.Minute})
	require.NoError(t, err)
	_, err = src.Manifest(context.Background())
	require.Error(t, err)
}

func TestNewHTTPManifestValidation(t *testing.T) {
	_, err := NewHTTPManifest(ManifestOptions{URL: "http://rgw.example.com/manifest.json"})
	require.ErrorContains(t, err, "https")
	_, err = NewHTTPManifest(ManifestOptions{URL: ""})
	require.Error(t, err)
	_, err = NewHTTPManifest(ManifestOptions{URL: "https://rgw.example.com/m.json", ChainAllowedPrefixes: []string{"https://x.example.com/no-slash"}})
	require.ErrorContains(t, err, "must end with /")
	_, err = NewHTTPManifest(ManifestOptions{URL: "https://rgw.example.com/m.json", CAFile: filepath.Join(t.TempDir(), "missing.pem")})
	require.Error(t, err)
}
