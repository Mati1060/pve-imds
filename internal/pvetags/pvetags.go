// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvetags reads the cluster-wide tag settings from
// /etc/pve/datacenter.cfg.
//
// Proxmox lets any user with VM.Config.Options on a VM set most tags, but
// tags listed in "registered-tags" can only be set or removed by users with
// Sys.Modify on "/". pve-imds can require a tag to be registered before it
// trusts it as a secret scope.
//
// Like user.cfg, datacenter.cfg lives on pmxcfs, where changes made on other
// nodes raise no inotify event, so it is re-read on every lookup.
package pvetags

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/spf13/afero"
)

// DefaultDatacenterCfgPath is the location of the cluster-wide options.
const DefaultDatacenterCfgPath = "/etc/pve/datacenter.cfg"

// Registry answers whether a tag is registered.
type Registry struct {
	fs   afero.Fs
	path string
}

// New returns a Registry that reads path from fs.
func New(fs afero.Fs, path string) *Registry {
	return &Registry{fs: fs, path: path}
}

// IsRegistered reports whether tag is listed in "registered-tags". Tags are
// compared case-insensitively unless "tag-style" sets case-sensitive=1, as
// Proxmox does. A missing datacenter.cfg means no tags are registered.
func (r *Registry) IsRegistered(tag string) (bool, error) {
	raw, err := afero.ReadFile(r.fs, r.path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pvetags: read %s: %w", r.path, err)
	}

	var registered []string
	caseSensitive := false

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, val, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "registered-tags":
			registered = strings.Split(val, ";")
		case "tag-style":
			for opt := range strings.SplitSeq(val, ",") {
				k, v, _ := strings.Cut(strings.TrimSpace(opt), "=")
				if k == "case-sensitive" {
					caseSensitive = v == "1"
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("pvetags: scan %s: %w", r.path, err)
	}

	for _, t := range registered {
		t = strings.TrimSpace(t)
		if t == tag || (!caseSensitive && strings.EqualFold(t, tag)) {
			return true, nil
		}
	}
	return false, nil
}
