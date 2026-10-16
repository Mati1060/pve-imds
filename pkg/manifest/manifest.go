// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package manifest parses and validates the PXE image manifest: the JSON
// document that lists the disk and chain images pve-imds can provision. It
// is importable so that tools which write the manifest validate it with
// the exact rules pve-imds applies when it reads it.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ImageType is how an image is provisioned.
type ImageType string

const (
	// TypeDisk is a raw.zst disk image written by the live OS.
	TypeDisk ImageType = "disk"
	// TypeChain is a remote iPXE target that iPXE chains into.
	TypeChain ImageType = "chain"
)

// BootMode says how often a chain image is chained.
type BootMode string

const (
	// BootOnce chains the image until the VM has a state record for it,
	// then boots from disk.
	BootOnce BootMode = "once"
	// BootAlways chains the image on every boot and keeps no state.
	BootAlways BootMode = "always"
)

// nameRe is the charset of image IDs and versions, shared with the
// <!--#pxe block.
var nameRe = regexp.MustCompile(`^[a-z0-9._-]+$`)

// sha256Re matches a hex SHA-256 digest.
var sha256Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// urlCharsRe is the charset allowed in URLs that end up in iPXE scripts:
// RFC 3986 characters without "$" (iPXE expands ${...}), quotes, "#" and
// anything iPXE would split on.
var urlCharsRe = regexp.MustCompile(`^[A-Za-z0-9\-._~:/?\[\]@!&()*+,;=%]+$`)

// Manifest lists the images that can be provisioned.
type Manifest struct {
	Images map[string]Image
}

// Image is one valid manifest entry.
type Image struct {
	Type ImageType
	// Boot is only set for chain images.
	Boot     BootMode
	Latest   string
	Versions map[string]Version
}

// Version is one version of an image. SHA256 and Size are only set for
// disk images; SHA256 is lowercase.
type Version struct {
	URL    string
	SHA256 string
	Size   int64
}

// Skipped describes a manifest entry that was left out because it is
// invalid.
type Skipped struct {
	// Image is the image ID; Version is empty when the whole image was
	// skipped.
	Image   string
	Version string
	Reason  string
}

type rawManifest struct {
	Images map[string]json.RawMessage `json:"images"`
}

type rawImage struct {
	Type     string                     `json:"type"`
	Boot     string                     `json:"boot"`
	Latest   string                     `json:"latest"`
	Versions map[string]json.RawMessage `json:"versions"`
}

type rawVersion struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// decodeStrict decodes data into v and rejects unknown fields and trailing
// data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Options are the deployment-specific rules a manifest is checked against.
type Options struct {
	// ChainAllowedPrefixes are the URL prefixes chain images may use (see
	// [ValidateAllowedPrefixes]).
	ChainAllowedPrefixes []string
	// DiskURLPrefix, if non-empty, is the prefix every disk image URL must
	// start with, typically the URL of the private image bucket ending in
	// "/".
	DiskURLPrefix string
}

// Parse parses and validates a manifest. A document that is not a valid
// manifest at all is an error. Invalid image or version entries are left
// out and reported in skipped; an image whose latest version is skipped or
// missing is skipped as a whole. A writer should treat any skipped entry
// as an error.
func Parse(data []byte, opts Options) (m *Manifest, skipped []Skipped, err error) {
	var raw rawManifest
	if err := decodeStrict(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("manifest: decode: %w", err)
	}
	if raw.Images == nil {
		return nil, nil, errors.New("manifest: no images object")
	}

	m = &Manifest{Images: make(map[string]Image, len(raw.Images))}
	for _, id := range sortedKeys(raw.Images) {
		img, imgSkipped, err := parseImage(id, raw.Images[id], opts)
		skipped = append(skipped, imgSkipped...)
		if err != nil {
			skipped = append(skipped, Skipped{Image: id, Reason: err.Error()})
			continue
		}
		m.Images[id] = img
	}
	return m, skipped, nil
}

func parseImage(id string, data json.RawMessage, opts Options) (Image, []Skipped, error) {
	if !nameRe.MatchString(id) {
		return Image{}, nil, fmt.Errorf("image id must match %s", nameRe)
	}
	var raw rawImage
	if err := decodeStrict(data, &raw); err != nil {
		return Image{}, nil, err
	}

	img := Image{Type: ImageType(raw.Type), Latest: raw.Latest}
	switch img.Type {
	case TypeDisk:
		if raw.Boot != "" {
			return Image{}, nil, errors.New("boot is only valid for chain images")
		}
	case TypeChain:
		switch BootMode(raw.Boot) {
		case "", BootOnce:
			img.Boot = BootOnce
		case BootAlways:
			img.Boot = BootAlways
		default:
			return Image{}, nil, fmt.Errorf("boot must be %q or %q", BootOnce, BootAlways)
		}
	default:
		return Image{}, nil, fmt.Errorf("type must be %q or %q", TypeDisk, TypeChain)
	}

	var skipped []Skipped
	img.Versions = make(map[string]Version, len(raw.Versions))
	for _, v := range sortedKeys(raw.Versions) {
		ver, err := parseVersion(img.Type, v, raw.Versions[v], opts)
		if err != nil {
			skipped = append(skipped, Skipped{Image: id, Version: v, Reason: err.Error()})
			continue
		}
		img.Versions[v] = ver
	}

	if img.Latest == "" {
		return Image{}, skipped, errors.New("latest is required")
	}
	if _, ok := img.Versions[img.Latest]; !ok {
		return Image{}, skipped, fmt.Errorf("latest %q is not a valid version", img.Latest)
	}
	return img, skipped, nil
}

func parseVersion(typ ImageType, v string, data json.RawMessage, opts Options) (Version, error) {
	if !nameRe.MatchString(v) {
		return Version{}, fmt.Errorf("version must match %s", nameRe)
	}
	var raw rawVersion
	if err := decodeStrict(data, &raw); err != nil {
		return Version{}, err
	}

	switch typ {
	case TypeDisk:
		if err := checkHTTPSURL(raw.URL); err != nil {
			return Version{}, err
		}
		if !strings.HasPrefix(raw.URL, opts.DiskURLPrefix) {
			return Version{}, fmt.Errorf("url %q is not below %s", raw.URL, opts.DiskURLPrefix)
		}
		if !sha256Re.MatchString(raw.SHA256) {
			return Version{}, errors.New("sha256 must be 64 hex characters")
		}
		if raw.Size <= 0 {
			return Version{}, errors.New("size must be greater than 0")
		}
		return Version{URL: raw.URL, SHA256: strings.ToLower(raw.SHA256), Size: raw.Size}, nil
	default:
		if raw.SHA256 != "" || raw.Size != 0 {
			return Version{}, errors.New("sha256 and size are only valid for disk images")
		}
		if err := CheckChainURL(raw.URL, opts.ChainAllowedPrefixes); err != nil {
			return Version{}, err
		}
		return Version{URL: raw.URL}, nil
	}
}

// checkHTTPSURL returns an error unless raw is an absolute https URL with a
// host, no user info, no "." or ".." path segments, and only characters
// that are safe in an iPXE script.
func checkHTTPSURL(raw string) error {
	if !urlCharsRe.MatchString(raw) {
		return fmt.Errorf("url %q contains characters outside %s", raw, urlCharsRe)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url %q: %w", raw, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("url %q must be an https URL with a host", raw)
	}
	for seg := range strings.SplitSeq(u.EscapedPath(), "/") {
		if s, _ := url.PathUnescape(seg); s == "." || s == ".." {
			return fmt.Errorf("url %q must not contain . or .. path segments", raw)
		}
	}
	return nil
}

// CheckChainURL returns an error unless raw is a safe https URL (see
// checkHTTPSURL) that starts with one of allowedPrefixes.
func CheckChainURL(raw string, allowedPrefixes []string) error {
	if err := checkHTTPSURL(raw); err != nil {
		return err
	}
	for _, p := range allowedPrefixes {
		if strings.HasPrefix(raw, p) {
			return nil
		}
	}
	return fmt.Errorf("chain url %q does not match chain_allowed_prefixes", raw)
}

// ValidateAllowedPrefixes returns an error unless every prefix is an https
// URL ending in "/".
func ValidateAllowedPrefixes(prefixes []string) error {
	for _, p := range prefixes {
		if err := checkHTTPSURL(p); err != nil {
			return fmt.Errorf("manifest: chain_allowed_prefixes: %w", err)
		}
		if !strings.HasSuffix(p, "/") {
			return fmt.Errorf("manifest: chain_allowed_prefixes: %q must end with /", p)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
