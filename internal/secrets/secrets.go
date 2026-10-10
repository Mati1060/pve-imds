// Package secrets resolves named secret sets for templated user-data and
// renders {{ secret "field" }} placeholders.
//
// A secret set is identified by the VM's Proxmox resource pool (read from
// Proxmox, never from VM-controlled input) and the set name from the VM's
// Notes. Sets are read from a [Source]; [KVv2] reads them from an
// OpenBao/Vault KV v2 secrets engine and [Cache] adds a short TTL in front of
// any Source.
package secrets

import (
	"context"
	"errors"
)

// Source fetches a secret set. Implementations must treat pool and set as
// already validated (see [ValidateSetName] and [ValidatePool]).
type Source interface {
	// Get returns the string fields of the set name in pool. It returns an
	// error wrapping ErrSetNotFound when the set does not exist.
	Get(ctx context.Context, pool, set string) (map[string]string, error)
}

var (
	// ErrSetNotFound is returned when a secret set does not exist.
	ErrSetNotFound = errors.New("secrets: secret set not found")

	// ErrInvalidSetName is returned for set names that fail validation.
	ErrInvalidSetName = errors.New("secrets: invalid secret set name")

	// ErrInvalidPool is returned for pool IDs that fail validation.
	ErrInvalidPool = errors.New("secrets: invalid pool id")

	// ErrMissingField is returned by Render when a placeholder references a
	// field that is not present in the set.
	ErrMissingField = errors.New("secrets: missing field")
)
