package secrets

import (
	"context"
	"errors"
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

// KVv2 reads secret sets from an OpenBao/Vault KV v2 secrets engine through
// a [KVClient].
type KVv2 struct {
	kv   *KVClient
	tmpl string
}

// NewKVv2 validates opts and returns a KVv2 source.
func NewKVv2(opts KVOptions) (*KVv2, error) {
	kv, err := NewKVClient(ConnOptions{
		Address:   opts.Address,
		Namespace: opts.Namespace,
		CAFile:    opts.CAFile,
		TokenFile: opts.TokenFile,
	})
	if err != nil {
		return nil, err
	}
	if _, err := TemplateScope(opts.PathTemplate); err != nil {
		return nil, err
	}
	return &KVv2{kv: kv, tmpl: opts.PathTemplate}, nil
}

// Get implements [Source]. Only string fields are returned; fields of any
// other type are dropped, so referencing one fails as a missing field.
func (k *KVv2) Get(ctx context.Context, scope Scope, set string) (map[string]string, error) {
	path, err := BuildPath(k.tmpl, scope, set)
	if err != nil {
		return nil, err
	}

	data, err := k.kv.Read(ctx, path)
	if errors.Is(err, ErrKVNotFound) {
		return nil, ErrSetNotFound
	}
	if err != nil {
		return nil, err
	}

	values := make(map[string]string, len(data))
	for f, v := range data {
		if s, ok := v.(string); ok {
			values[f] = s
		}
	}
	return values, nil
}
