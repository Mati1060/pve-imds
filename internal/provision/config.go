// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package provision

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/s3"
)

// FromConfig builds a Provisioner from cfg, reading and writing state
// records in state. liveUKIURL is what iPXE chains to boot the live OS.
// With pxe.images.bucket_url set, the image bucket's keys are read from
// OpenBao with the connection settings of conn. It validates the
// configuration but does not fetch the manifest, the bucket keys or the
// live UKI, which are all checked per request.
func FromConfig(cfg config.PXEConfig, conn config.SecretsConfig, state StateStore, liveUKIURL string, log *slog.Logger) (*Provisioner, error) {
	if cfg.ManifestURL == "" {
		return nil, errors.New("provision: pxe.manifest_url is required")
	}
	if cfg.LiveUKI == "" {
		return nil, errors.New("provision: pxe.live_uki is required")
	}
	mopts := ManifestOptions{
		URL:                  cfg.ManifestURL,
		CAFile:               cfg.ManifestCAFile,
		TTL:                  cfg.ManifestTTL,
		ChainAllowedPrefixes: cfg.ChainAllowedPrefixes,
		Log:                  log,
	}
	opts := Options{
		State:                state,
		LiveUKI:              cfg.LiveUKI,
		LiveUKIURL:           liveUKIURL,
		ChainAllowedPrefixes: cfg.ChainAllowedPrefixes,
	}

	bucket, err := s3.FromConfig(cfg.Images, conn)
	if err != nil {
		return nil, err
	}
	if bucket != nil {
		if !bucket.Contains(cfg.ManifestURL) {
			return nil, fmt.Errorf("provision: pxe.manifest_url must be in pxe.images.bucket_url %s", bucket.URL())
		}
		mopts.DiskURLPrefix = bucket.URL()
		mopts.Sign = bucket.SignRequest
		opts.Images = bucket
	}

	opts.Manifests, err = NewHTTPManifest(mopts)
	if err != nil {
		return nil, err
	}
	return New(opts), nil
}
