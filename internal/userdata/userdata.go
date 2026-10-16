// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package userdata implements [imds.UserDataProvider]: it extracts the
// <!--#user-data block from a VM's Notes and, when the block declares
// secrets=<set>, renders its {{ secret "field" }} placeholders from the
// secret set in the VM's scope: its resource pool or a prefixed tag.
//
// Rendering fails closed: any problem (secrets disabled, no scope, invalid
// set name, unreachable server, missing set or field) yields
// [imds.ErrUserDataUnavailable] and no content. Only the VMID, scope, set
// name and outcome are logged, never user-data or secret values.
package userdata

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/afero"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/pvepool"
	"github.com/wyattanderson/pve-imds/internal/pvetags"
	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// Provider implements [imds.UserDataProvider].
type Provider struct {
	log    *slog.Logger
	source secrets.Source
	scopes ScopeResolver
}

// New returns a Provider. A nil source means templating is disabled: blocks
// without secrets= are served as-is and blocks with it are unavailable.
// scopes may be nil only when source is nil.
func New(log *slog.Logger, source secrets.Source, scopes ScopeResolver) *Provider {
	return &Provider{log: log, source: source, scopes: scopes}
}

// UserData implements [imds.UserDataProvider].
func (p *Provider) UserData(ctx context.Context, rec *identity.VMRecord) (string, error) {
	blk, ok := imds.ParseUserDataBlock(rec.Config.Description)
	if !ok {
		return "", imds.ErrNoUserData
	}
	if !blk.Templated {
		return blk.Content, nil
	}

	log := p.log.With("vmid", rec.VMID, "set", blk.SecretSet)
	fail := func(outcome string, err error, extra ...any) (string, error) {
		args := append([]any{"outcome", outcome}, extra...)
		if err != nil {
			args = append(args, "err", err)
		}
		log.WarnContext(ctx, "user-data: templating failed", args...)
		return "", fmt.Errorf("%w: %s", imds.ErrUserDataUnavailable, outcome)
	}

	if p.source == nil {
		return fail("secrets_disabled", nil)
	}
	if err := secrets.ValidateSetName(blk.SecretSet); err != nil {
		return fail("invalid_set_name", nil)
	}

	scope, err := p.scopes.ScopeOf(rec)
	if err != nil {
		if se, ok := errors.AsType[*ScopeError](err); ok {
			return fail(se.Outcome, se.Err)
		}
		return fail("scope_lookup_failed", err)
	}
	log = log.With(string(scope.Kind), scope.Name)

	values, err := p.source.Get(ctx, scope, blk.SecretSet)
	if err != nil {
		return fail("secret_fetch_failed", err)
	}

	out, err := secrets.Render(blk.Content, values)
	if err != nil {
		return fail("render_failed", err)
	}

	log.InfoContext(ctx, "user-data: rendered", "outcome", "ok")
	return out, nil
}

// FromConfig builds a Provider from cfg. When secrets are disabled the
// Provider serves user-data without templating. When they are enabled it
// reads secret sets through a TTL cache from an OpenBao/Vault KV v2 server.
// The path template decides the scope: {pool} resolves pools from
// /etc/pve/user.cfg, {tag} uses the VM tag starting with cfg.TagPrefix,
// checked against /etc/pve/datacenter.cfg when cfg.RequireRegisteredTags.
func FromConfig(cfg config.SecretsConfig, fs afero.Fs, log *slog.Logger) (*Provider, error) {
	if !cfg.Enabled {
		return New(log, nil, nil), nil
	}

	kv, err := secrets.NewKVv2(secrets.KVOptions{
		Address:      cfg.Address,
		Namespace:    cfg.Namespace,
		CAFile:       cfg.CAFile,
		TokenFile:    cfg.TokenFile,
		PathTemplate: cfg.PathTemplate,
	})
	if err != nil {
		return nil, err
	}
	var scopes ScopeResolver
	switch kv.ScopeKind() {
	case secrets.ScopePool:
		scopes = PoolScope{Pools: pvepool.New(fs, pvepool.DefaultUserCfgPath)}
	case secrets.ScopeTag:
		if cfg.TagPrefix == "" {
			return nil, errors.New("secrets: tag_prefix must not be empty when path_template uses {tag}")
		}
		ts := TagScope{Prefix: cfg.TagPrefix}
		if cfg.RequireRegisteredTags {
			ts.Registry = pvetags.New(fs, pvetags.DefaultDatacenterCfgPath)
		}
		scopes = ts
	}
	return New(log, secrets.NewCache(kv, cfg.CacheTTL), scopes), nil
}
