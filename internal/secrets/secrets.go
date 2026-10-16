// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secrets resolves named secret sets for templated user-data and
// renders {{ secret "field" }} placeholders.
//
// A secret set is identified by a [Scope] — the VM's Proxmox resource pool or
// one of its tags, both read from Proxmox, never from VM-controlled input —
// and the set name from the VM's Notes. Sets are read from a [Source]; [KVv2]
// reads them from an OpenBao/Vault KV v2 secrets engine and [Cache] adds a
// short TTL in front of any Source.
package secrets

import (
	"context"
	"errors"
)

// ScopeKind is what a secret set is scoped to.
type ScopeKind string

const (
	// ScopePool scopes secret sets to the VM's Proxmox resource pool. Path
	// templates use the {pool} variable.
	ScopePool ScopeKind = "pool"

	// ScopeTag scopes secret sets to a VM tag. Path templates use the {tag}
	// variable.
	ScopeTag ScopeKind = "tag"
)

// Scope identifies the namespace a VM's secret sets live in.
type Scope struct {
	Kind ScopeKind
	// Name is the pool ID or the tag (without its prefix).
	Name string
}

// Source fetches a secret set. Implementations must validate scope and set
// (see [ValidateScope] and [ValidateSetName]) before using them.
type Source interface {
	// Get returns the string fields of the set name in scope. It returns an
	// error wrapping ErrSetNotFound when the set does not exist.
	Get(ctx context.Context, scope Scope, set string) (map[string]string, error)
}

var (
	// ErrSetNotFound is returned when a secret set does not exist.
	ErrSetNotFound = errors.New("secrets: secret set not found")

	// ErrInvalidSetName is returned for set names that fail validation.
	ErrInvalidSetName = errors.New("secrets: invalid secret set name")

	// ErrInvalidScope is returned for pool IDs or tags that fail validation,
	// or for a scope kind that does not match the path template.
	ErrInvalidScope = errors.New("secrets: invalid scope")

	// ErrMissingField is returned by Render when a placeholder references a
	// field that is not present in the set.
	ErrMissingField = errors.New("secrets: missing field")
)
