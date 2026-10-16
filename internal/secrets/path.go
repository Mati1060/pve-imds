// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// setNameRe is the charset allowed for set names: no '/', no '.', so a set
// name can never leave its pool's prefix.
var setNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

// poolSegmentRe mirrors the per-segment charset Proxmox enforces for pool IDs
// (PVE::AccessControl::verify_poolname).
var poolSegmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// tagRe is the charset Proxmox allows in tags (PVE::JSONSchema PVE_TAG_RE,
// case-insensitive). Tags never contain '/'.
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_+.-]+$`)

// maxPoolDepth is the maximum nesting depth Proxmox allows for pools.
const maxPoolDepth = 3

// templateVarRe matches {var} placeholders in a path template.
var templateVarRe = regexp.MustCompile(`\{[^{}]*\}`)

// ValidateSetName returns an error wrapping ErrInvalidSetName unless name is
// 1–64 characters of [A-Za-z0-9_-], starting with a letter or digit.
func ValidateSetName(name string) error {
	if !setNameRe.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidSetName, name)
	}
	return nil
}

// ValidateScope returns an error wrapping ErrInvalidScope unless scope.Name
// is valid for its kind.
//
// A pool ID must be 1–3 '/'-separated segments of [A-Za-z0-9._-]. A tag must
// be a single segment of [A-Za-z0-9_+.-]. Both come from Proxmox and are
// trusted, but "." and ".." are rejected anyway because Proxmox would accept
// them and they have a special meaning in paths.
func ValidateScope(scope Scope) error {
	var segs []string
	switch scope.Kind {
	case ScopePool:
		segs = strings.Split(scope.Name, "/")
		if len(segs) > maxPoolDepth {
			return fmt.Errorf("%w: pool %q nested too deeply", ErrInvalidScope, scope.Name)
		}
	case ScopeTag:
		segs = []string{scope.Name}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidScope, scope.Kind)
	}

	re := poolSegmentRe
	if scope.Kind == ScopeTag {
		re = tagRe
	}
	for _, s := range segs {
		if !re.MatchString(s) || s == "." || s == ".." {
			return fmt.Errorf("%w: %s %q", ErrInvalidScope, scope.Kind, scope.Name)
		}
	}
	return nil
}

// TemplateScope validates tmpl and returns the scope kind it uses. A template
// must contain {name} and exactly one of {pool} or {tag}, and no other
// variables.
func TemplateScope(tmpl string) (ScopeKind, error) {
	for _, v := range templateVarRe.FindAllString(tmpl, -1) {
		if v != "{pool}" && v != "{tag}" && v != "{name}" {
			return "", fmt.Errorf("secrets: path template %q contains unknown variable %s", tmpl, v)
		}
	}
	hasPool := strings.Contains(tmpl, "{pool}")
	hasTag := strings.Contains(tmpl, "{tag}")
	switch {
	case !strings.Contains(tmpl, "{name}"):
		return "", fmt.Errorf("secrets: path template %q must contain {name}", tmpl)
	case hasPool == hasTag:
		return "", fmt.Errorf("secrets: path template %q must contain exactly one of {pool} or {tag}", tmpl)
	case hasPool:
		return ScopePool, nil
	default:
		return ScopeTag, nil
	}
}

// BuildPath expands tmpl for scope and set. Both are validated, the scope kind
// must match the template, and every segment is path-escaped, so the result
// always stays below the template's fixed prefix. Nested pools
// ("parent/child") expand to one path segment per pool level.
func BuildPath(tmpl string, scope Scope, set string) (string, error) {
	kind, err := TemplateScope(tmpl)
	if err != nil {
		return "", err
	}
	if kind != scope.Kind {
		return "", fmt.Errorf("%w: template uses {%s}, got a %s scope", ErrInvalidScope, kind, scope.Kind)
	}
	if err := ValidateScope(scope); err != nil {
		return "", err
	}
	if err := ValidateSetName(set); err != nil {
		return "", err
	}

	segs := strings.Split(scope.Name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}

	return strings.NewReplacer(
		"{"+string(kind)+"}", strings.Join(segs, "/"),
		"{name}", url.PathEscape(set),
	).Replace(strings.Trim(tmpl, "/")), nil
}
