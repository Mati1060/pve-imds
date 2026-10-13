package provision

import (
	"errors"
	"log/slog"

	"github.com/wyattanderson/pve-imds/internal/config"
)

// FromConfig builds a Provisioner from cfg, reading and writing state
// records in state. liveUKIURL is what iPXE chains to boot the live OS. It
// validates manifest_url and chain_allowed_prefixes but does not fetch the
// manifest or check the live UKI, which are both checked per request.
func FromConfig(cfg config.PXEConfig, state StateStore, liveUKIURL string, log *slog.Logger) (*Provisioner, error) {
	if cfg.ManifestURL == "" {
		return nil, errors.New("provision: pxe.manifest_url is required")
	}
	if cfg.LiveUKI == "" {
		return nil, errors.New("provision: pxe.live_uki is required")
	}
	manifests, err := NewHTTPManifest(ManifestOptions{
		URL:                  cfg.ManifestURL,
		CAFile:               cfg.ManifestCAFile,
		TTL:                  cfg.ManifestTTL,
		ChainAllowedPrefixes: cfg.ChainAllowedPrefixes,
		Log:                  log,
	})
	if err != nil {
		return nil, err
	}
	return New(Options{
		Manifests:            manifests,
		State:                state,
		LiveUKI:              cfg.LiveUKI,
		LiveUKIURL:           liveUKIURL,
		ChainAllowedPrefixes: cfg.ChainAllowedPrefixes,
	}), nil
}
