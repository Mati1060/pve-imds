package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// kvRequestTimeout bounds a single request to the KV server.
	kvRequestTimeout = 10 * time.Second

	// kvMaxResponseBytes bounds how much of a response body is read.
	kvMaxResponseBytes = 1 << 20
)

// ScopeKind returns the scope kind the path template uses.
func (k *KVv2) ScopeKind() ScopeKind {
	kind, _ := TemplateScope(k.tmpl) // validated in NewKVv2
	return kind
}

// KVOptions configures a [KVv2] source.
type KVOptions struct {
	// Address is the server base URL; it must use https.
	Address string
	// Namespace, if non-empty, is sent as X-Vault-Namespace.
	Namespace string
	// CAFile is an optional PEM bundle for verifying the server.
	CAFile string
	// TokenFile is read on every request.
	TokenFile string
	// PathTemplate is the API path below /v1/; see [BuildPath].
	PathTemplate string
}

// KVv2 reads secret sets from an OpenBao/Vault KV v2 secrets engine. It
// contains no authentication logic: the token is read from a file that is
// expected to be kept up to date by OpenBao Agent or similar.
type KVv2 struct {
	base      *url.URL
	namespace string
	tokenFile string
	tmpl      string
	client    *http.Client
}

// NewKVv2 validates opts and returns a KVv2 source.
func NewKVv2(opts KVOptions) (*KVv2, error) {
	base, err := url.Parse(opts.Address)
	if err != nil {
		return nil, fmt.Errorf("secrets: parse address: %w", err)
	}
	if base.Scheme != "https" || base.Host == "" {
		return nil, fmt.Errorf("secrets: address %q must be an https URL", opts.Address)
	}
	if opts.TokenFile == "" {
		return nil, errors.New("secrets: token_file is required")
	}
	if _, err := TemplateScope(opts.PathTemplate); err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("secrets: read ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("secrets: no certificates found in %s", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	// The server is addressed directly; never route secrets via a proxy
	// picked up from the environment.
	transport.Proxy = nil

	return &KVv2{
		base:      base,
		namespace: opts.Namespace,
		tokenFile: opts.TokenFile,
		tmpl:      opts.PathTemplate,
		client:    &http.Client{Transport: transport, Timeout: kvRequestTimeout},
	}, nil
}

// kvResponse is the subset of a KV v2 read response that we use.
type kvResponse struct {
	Data struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
}

// Get implements [Source]. Only string fields are returned; fields of any
// other type are dropped, so referencing one fails as a missing field.
func (k *KVv2) Get(ctx context.Context, scope Scope, set string) (map[string]string, error) {
	path, err := BuildPath(k.tmpl, scope, set)
	if err != nil {
		return nil, err
	}

	token, err := k.readToken()
	if err != nil {
		return nil, err
	}

	// path is already escaped by BuildPath, so join it as a string rather
	// than through url.URL.JoinPath, which would escape it again.
	endpoint := strings.TrimSuffix(k.base.String(), "/") + "/v1/" + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	if k.namespace != "" {
		req.Header.Set("X-Vault-Namespace", k.namespace)
	}

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, kvMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("secrets: read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrSetNotFound
	default:
		// The body may echo request details; report only the status.
		return nil, fmt.Errorf("secrets: server returned %s", resp.Status)
	}

	var kr kvResponse
	if err := json.Unmarshal(body, &kr); err != nil {
		return nil, fmt.Errorf("secrets: decode response: %w", err)
	}
	// A deleted or destroyed latest version is returned with null data.
	if kr.Data.Data == nil {
		return nil, ErrSetNotFound
	}

	values := make(map[string]string, len(kr.Data.Data))
	for f, v := range kr.Data.Data {
		if s, ok := v.(string); ok {
			values[f] = s
		}
	}
	return values, nil
}

// readToken reads the token file. It is read on every request so that a
// token renewed by OpenBao Agent takes effect immediately.
func (k *KVv2) readToken() (string, error) {
	b, err := os.ReadFile(k.tokenFile)
	if err != nil {
		return "", fmt.Errorf("secrets: read token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("secrets: token file is empty")
	}
	return token, nil
}
