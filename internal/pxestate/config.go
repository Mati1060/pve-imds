// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package pxestate

import (
	"errors"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// FromConfig builds a Store from cfg, connecting with the address, token
// file, CA file and namespace of conn. It returns (nil, nil) when cfg is
// disabled. Templating (conn.Enabled) does not need to be on.
func FromConfig(cfg config.PXEConfig, conn config.SecretsConfig) (*Store, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if conn.Address == "" || conn.TokenFile == "" {
		return nil, errors.New("pxe: pxe.enabled requires secrets.address and secrets.token_file")
	}
	kv, err := secrets.NewKVClient(secrets.ConnOptions{
		Address:   conn.Address,
		Namespace: conn.Namespace,
		CAFile:    conn.CAFile,
		TokenFile: conn.TokenFile,
	})
	if err != nil {
		return nil, err
	}
	return New(kv, cfg.StatePathTemplate)
}
