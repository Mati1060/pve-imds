package userdata

import (
	"strings"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// ScopeResolver determines which secret scope a VM belongs to. It must only
// use data from Proxmox, never anything the VM controls.
type ScopeResolver interface {
	// ScopeOf returns the VM's scope. Errors should be *ScopeError so the
	// outcome can be logged.
	ScopeOf(rec *identity.VMRecord) (secrets.Scope, error)
}

// ScopeError explains why a VM has no usable scope.
type ScopeError struct {
	// Outcome is a short machine-readable reason, logged as "outcome".
	Outcome string
	// Err is the underlying error, if any.
	Err error
}

func (e *ScopeError) Error() string {
	if e.Err != nil {
		return e.Outcome + ": " + e.Err.Error()
	}
	return e.Outcome
}

func (e *ScopeError) Unwrap() error { return e.Err }

// PoolLookup resolves a VM's Proxmox resource pool.
type PoolLookup interface {
	PoolOf(vmid int) (pool string, ok bool, err error)
}

// PoolScope scopes secrets to the VM's resource pool.
type PoolScope struct {
	Pools PoolLookup
}

// ScopeOf implements [ScopeResolver].
func (s PoolScope) ScopeOf(rec *identity.VMRecord) (secrets.Scope, error) {
	pool, ok, err := s.Pools.PoolOf(rec.VMID)
	if err != nil {
		return secrets.Scope{}, &ScopeError{Outcome: "pool_lookup_failed", Err: err}
	}
	if !ok {
		return secrets.Scope{}, &ScopeError{Outcome: "vm_not_in_pool"}
	}
	return secrets.Scope{Kind: secrets.ScopePool, Name: pool}, nil
}

// TagRegistry reports whether a tag is registered (settable only by users
// with Sys.Modify on "/").
type TagRegistry interface {
	IsRegistered(tag string) (bool, error)
}

// TagScope scopes secrets to the one VM tag that starts with Prefix; the
// scope name is the rest of the tag, lowercased. A VM with no such tag, or
// more than one, has no scope. When Registry is non-nil the tag must also be
// registered.
type TagScope struct {
	Prefix   string
	Registry TagRegistry
}

// ScopeOf implements [ScopeResolver].
func (s TagScope) ScopeOf(rec *identity.VMRecord) (secrets.Scope, error) {
	prefix := strings.ToLower(s.Prefix)
	var match, name string
	for _, t := range rec.Config.Tags {
		rest, ok := strings.CutPrefix(strings.ToLower(t), prefix)
		if !ok || rest == "" || rest == name {
			continue
		}
		if name != "" {
			return secrets.Scope{}, &ScopeError{Outcome: "multiple_scope_tags"}
		}
		match, name = t, rest
	}
	if name == "" {
		return secrets.Scope{}, &ScopeError{Outcome: "no_scope_tag"}
	}

	if s.Registry != nil {
		ok, err := s.Registry.IsRegistered(match)
		if err != nil {
			return secrets.Scope{}, &ScopeError{Outcome: "tag_lookup_failed", Err: err}
		}
		if !ok {
			return secrets.Scope{}, &ScopeError{Outcome: "tag_not_registered"}
		}
	}
	return secrets.Scope{Kind: secrets.ScopeTag, Name: name}, nil
}
