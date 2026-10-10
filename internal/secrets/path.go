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

// ValidatePool returns an error wrapping ErrInvalidPool unless pool is a
// valid Proxmox pool ID: 1–3 '/'-separated segments of [A-Za-z0-9._-]. Pool
// IDs come from Proxmox and are trusted, but "." and ".." segments are
// rejected anyway because Proxmox would accept them and they have a special
// meaning in paths.
func ValidatePool(pool string) error {
	segs := strings.Split(pool, "/")
	if len(segs) > maxPoolDepth {
		return fmt.Errorf("%w: %q nested too deeply", ErrInvalidPool, pool)
	}
	for _, s := range segs {
		if !poolSegmentRe.MatchString(s) || s == "." || s == ".." {
			return fmt.Errorf("%w: %q", ErrInvalidPool, pool)
		}
	}
	return nil
}

// ValidatePathTemplate checks that tmpl contains both {pool} and {name} and no
// other variables.
func ValidatePathTemplate(tmpl string) error {
	if !strings.Contains(tmpl, "{pool}") || !strings.Contains(tmpl, "{name}") {
		return fmt.Errorf("secrets: path template %q must contain {pool} and {name}", tmpl)
	}
	for _, v := range templateVarRe.FindAllString(tmpl, -1) {
		if v != "{pool}" && v != "{name}" {
			return fmt.Errorf("secrets: path template %q contains unknown variable %s", tmpl, v)
		}
	}
	return nil
}

// BuildPath expands tmpl for pool and set. Both are validated, and every
// pool segment and the set name are path-escaped, so the result always stays
// below the template's fixed prefix. Nested pools ("parent/child") expand to
// one path segment per pool level.
func BuildPath(tmpl, pool, set string) (string, error) {
	if err := ValidatePool(pool); err != nil {
		return "", err
	}
	if err := ValidateSetName(set); err != nil {
		return "", err
	}

	segs := strings.Split(pool, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}

	return strings.NewReplacer(
		"{pool}", strings.Join(segs, "/"),
		"{name}", url.PathEscape(set),
	).Replace(strings.Trim(tmpl, "/")), nil
}
