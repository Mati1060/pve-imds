// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"bytes"
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

// ErrKVNotFound is returned by [KVClient.Read] when the path has no data:
// the server answered 404, or the latest version was deleted or destroyed.
var ErrKVNotFound = errors.New("secrets: kv entry not found")

// ConnOptions configures the connection to an OpenBao/Vault server.
type ConnOptions struct {
	// Address is the server base URL; it must use https.
	Address string
	// Namespace, if non-empty, is sent as X-Vault-Namespace.
	Namespace string
	// CAFile is an optional PEM bundle for verifying the server.
	CAFile string
	// TokenFile is read on every request.
	TokenFile string
	// Timeout bounds a single request. Zero means 10s.
	Timeout time.Duration
}

// KVClient reads and writes entries of an OpenBao/Vault KV v2 secrets engine.
// It contains no authentication logic: the token is read from a file that is
// expected to be kept up to date by OpenBao Agent or similar. Callers build
// and escape the API paths it is given.
type KVClient struct {
	base      *url.URL
	namespace string
	tokenFile string
	client    *http.Client
}

// NewKVClient validates opts and returns a KVClient.
func NewKVClient(opts ConnOptions) (*KVClient, error) {
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

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = kvRequestTimeout
	}

	return &KVClient{
		base:      base,
		namespace: opts.Namespace,
		tokenFile: opts.TokenFile,
		client:    &http.Client{Transport: transport, Timeout: timeout},
	}, nil
}

// kvResponse is the subset of a KV v2 read response that we use.
type kvResponse struct {
	Data struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
}

// Read returns the latest version's data at path, the API path below /v1/
// (e.g. "kv/data/x"). It returns an error wrapping [ErrKVNotFound] when
// there is no data; any other failure is an error.
func (c *KVClient) Read(ctx context.Context, path string) (map[string]any, error) {
	status, body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	switch status.code {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrKVNotFound
	default:
		// The body may echo request details; report only the status.
		return nil, fmt.Errorf("secrets: server returned %s", status.text)
	}

	var kr kvResponse
	if err := json.Unmarshal(body, &kr); err != nil {
		return nil, fmt.Errorf("secrets: decode response: %w", err)
	}
	// A deleted or destroyed latest version is returned with null data.
	if kr.Data.Data == nil {
		return nil, ErrKVNotFound
	}
	return kr.Data.Data, nil
}

// Write stores data as a new version at path, the API path below /v1/.
func (c *KVClient) Write(ctx context.Context, path string, data map[string]string) error {
	payload, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return fmt.Errorf("secrets: encode request: %w", err)
	}
	status, _, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return err
	}
	if status.code != http.StatusOK && status.code != http.StatusNoContent {
		return fmt.Errorf("secrets: server returned %s", status.text)
	}
	return nil
}

type httpStatus struct {
	code int
	text string
}

// do sends one authenticated request and returns the status and the
// (size-limited) response body.
func (c *KVClient) do(ctx context.Context, method, path string, payload []byte) (httpStatus, []byte, error) {
	token, err := c.readToken()
	if err != nil {
		return httpStatus{}, nil, err
	}

	// path is already escaped by the caller, so join it as a string rather
	// than through url.URL.JoinPath, which would escape it again.
	endpoint := strings.TrimSuffix(c.base.String(), "/") + "/v1/" + strings.TrimPrefix(path, "/")

	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return httpStatus{}, nil, fmt.Errorf("secrets: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return httpStatus{}, nil, fmt.Errorf("secrets: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, kvMaxResponseBytes))
	if err != nil {
		return httpStatus{}, nil, fmt.Errorf("secrets: read response: %w", err)
	}
	return httpStatus{code: resp.StatusCode, text: resp.Status}, respBody, nil
}

// readToken reads the token file. It is read on every request so that a
// token renewed by OpenBao Agent takes effect immediately.
func (c *KVClient) readToken() (string, error) {
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", fmt.Errorf("secrets: read token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", errors.New("secrets: token file is empty")
	}
	return token, nil
}
