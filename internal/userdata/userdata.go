// Package userdata implements [imds.UserDataProvider]: it extracts the
// <!--#user-data block from a VM's Notes and, when the block declares
// secrets=<set>, renders its {{ secret "field" }} placeholders from the VM's
// pool-scoped secret set.
//
// Rendering fails closed: any problem (secrets disabled, VM not in a pool,
// invalid set name, unreachable server, missing set or field) yields
// [imds.ErrUserDataUnavailable] and no content. Only the VMID, pool, set name
// and outcome are logged, never user-data or secret values.
package userdata

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/spf13/afero"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/pvepool"
	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// PoolLookup resolves a VM's Proxmox resource pool.
type PoolLookup interface {
	PoolOf(vmid int) (pool string, ok bool, err error)
}

// Provider implements [imds.UserDataProvider].
type Provider struct {
	log    *slog.Logger
	source secrets.Source
	pools  PoolLookup
}

// New returns a Provider. A nil source means templating is disabled: blocks
// without secrets= are served as-is and blocks with it are unavailable. pools
// may be nil only when source is nil.
func New(log *slog.Logger, source secrets.Source, pools PoolLookup) *Provider {
	return &Provider{log: log, source: source, pools: pools}
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

	pool, inPool, err := p.pools.PoolOf(rec.VMID)
	if err != nil {
		return fail("pool_lookup_failed", err)
	}
	if !inPool {
		return fail("vm_not_in_pool", nil)
	}
	log = log.With("pool", pool)

	values, err := p.source.Get(ctx, pool, blk.SecretSet)
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
// reads secret sets through a TTL cache from an OpenBao/Vault KV v2 server
// and resolves pools from /etc/pve/user.cfg on fs.
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
	return New(log, secrets.NewCache(kv, cfg.CacheTTL), pvepool.New(fs, pvepool.DefaultUserCfgPath)), nil
}
