package provision

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// manifestRequestTimeout bounds a single manifest fetch.
	manifestRequestTimeout = 10 * time.Second

	// manifestMaxBytes bounds the size of a manifest.
	manifestMaxBytes = 4 << 20
)

// ManifestSource returns the current manifest.
type ManifestSource interface {
	Manifest(ctx context.Context) (*Manifest, error)
}

// ManifestOptions configures an [HTTPManifest].
type ManifestOptions struct {
	// URL is the manifest URL; it must use https.
	URL string
	// CAFile is an optional PEM bundle for verifying the server. Empty
	// means the system trust store.
	CAFile string
	// TTL is how long a fetched manifest is reused. Zero or less disables
	// caching.
	TTL time.Duration
	// ChainAllowedPrefixes are the URL prefixes chain images may use.
	ChainAllowedPrefixes []string
	// Log receives a warning for every skipped manifest entry.
	Log *slog.Logger
	// Timeout bounds a single fetch. Zero means 10s.
	Timeout time.Duration
}

// HTTPManifest fetches the manifest over HTTPS and caches it for a TTL.
// Errors are never cached, and an expired manifest is never served when a
// fetch fails. Concurrent fetches share one request.
type HTTPManifest struct {
	url      string
	ttl      time.Duration
	prefixes []string
	log      *slog.Logger
	client   *http.Client
	now      func() time.Time

	group singleflight.Group

	mu      sync.Mutex
	cached  *Manifest
	expires time.Time
}

// NewHTTPManifest validates opts and returns an HTTPManifest. It does not
// fetch the manifest.
func NewHTTPManifest(opts ManifestOptions) (*HTTPManifest, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("provision: manifest_url %q must be an https URL", opts.URL)
	}
	if err := ValidateAllowedPrefixes(opts.ChainAllowedPrefixes); err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("provision: read manifest_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("provision: no certificates found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	transport.Proxy = nil

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = manifestRequestTimeout
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	return &HTTPManifest{
		url:      opts.URL,
		ttl:      opts.TTL,
		prefixes: opts.ChainAllowedPrefixes,
		log:      log,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// The manifest URL is configured; don't follow redirects to
			// another location.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}, nil
}

// Manifest implements [ManifestSource].
func (h *HTTPManifest) Manifest(ctx context.Context) (*Manifest, error) {
	h.mu.Lock()
	if h.cached != nil && h.now().Before(h.expires) {
		m := h.cached
		h.mu.Unlock()
		return m, nil
	}
	h.cached = nil
	h.mu.Unlock()

	v, err, _ := h.group.Do("manifest", func() (any, error) {
		m, err := h.fetch(ctx)
		if err != nil {
			return nil, err
		}
		if h.ttl > 0 {
			h.mu.Lock()
			h.cached, h.expires = m, h.now().Add(h.ttl)
			h.mu.Unlock()
		}
		return m, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Manifest), nil
}

func (h *HTTPManifest) fetch(ctx context.Context) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url, nil)
	if err != nil {
		return nil, fmt.Errorf("provision: build manifest request: %w", err)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provision: fetch manifest: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("provision: fetch manifest: server returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, manifestMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("provision: read manifest: %w", err)
	}
	if len(data) > manifestMaxBytes {
		return nil, errors.New("provision: manifest is larger than 4 MiB")
	}

	m, skipped, err := ParseManifest(data, h.prefixes)
	if err != nil {
		return nil, err
	}
	for _, s := range skipped {
		h.log.WarnContext(ctx, "pxe: skipping invalid manifest entry", "image", s.Image, "version", s.Version, "reason", s.Reason)
	}
	return m, nil
}
