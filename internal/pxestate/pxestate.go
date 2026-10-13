// Package pxestate records which image a VM was provisioned with. Records
// live in an OpenBao/Vault KV v2 secrets engine, keyed by the VM's SMBIOS
// UUID, so pve-imds never writes to Proxmox.
//
// State reads are never cached: the /pxe decision must reflect the record
// as it is now.
package pxestate

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// DefaultPathTemplate is the default API path (below /v1/) of a record.
const DefaultPathTemplate = "kv/data/pve-imds/pxe/{uuid}"

// uuidRe matches a lowercase RFC 4122 textual UUID.
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// nilUUID is shared by every VM that has one, so it cannot key a record.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// templateVarRe matches {var} placeholders in a path template.
var templateVarRe = regexp.MustCompile(`\{[^{}]*\}`)

// ErrInvalidUUID is returned for a UUID that cannot key a record.
var ErrInvalidUUID = errors.New("pxestate: invalid uuid")

// Record is the provisioning state of one VM.
type Record struct {
	// Image is the image the VM was provisioned with.
	Image string
	// Version is the image version that was installed.
	Version string
	// SHA256 is the digest of the installed image.
	SHA256 string
	// ProvisionedAt is when provisioning finished.
	ProvisionedAt time.Time
	// Method is how the VM was provisioned: "disk" or "chain".
	Method string
}

// Store reads and writes provisioning records.
type Store struct {
	kv   *secrets.KVClient
	tmpl string
}

// New returns a Store that keeps records in kv at paths built from tmpl,
// which must contain {uuid} and no other variable.
func New(kv *secrets.KVClient, tmpl string) (*Store, error) {
	if err := ValidatePathTemplate(tmpl); err != nil {
		return nil, err
	}
	return &Store{kv: kv, tmpl: tmpl}, nil
}

// ValidatePathTemplate returns an error unless tmpl contains {uuid} and no
// other variable.
func ValidatePathTemplate(tmpl string) error {
	for _, v := range templateVarRe.FindAllString(tmpl, -1) {
		if v != "{uuid}" {
			return fmt.Errorf("pxestate: path template %q contains unknown variable %s", tmpl, v)
		}
	}
	if !strings.Contains(tmpl, "{uuid}") {
		return fmt.Errorf("pxestate: path template %q must contain {uuid}", tmpl)
	}
	return nil
}

// NormalizeUUID lowercases uuid and returns an error wrapping
// [ErrInvalidUUID] unless it is a textual UUID other than the nil UUID.
func NormalizeUUID(uuid string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(uuid))
	if !uuidRe.MatchString(u) || u == nilUUID {
		return "", fmt.Errorf("%w: %q", ErrInvalidUUID, uuid)
	}
	return u, nil
}

func (s *Store) path(uuid string) (string, error) {
	u, err := NormalizeUUID(uuid)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(strings.Trim(s.tmpl, "/"), "{uuid}", url.PathEscape(u)), nil
}

// Get returns the record for uuid. found is false, with a nil error, when
// there is no record. Any other failure is an error.
func (s *Store) Get(ctx context.Context, uuid string) (rec Record, found bool, err error) {
	path, err := s.path(uuid)
	if err != nil {
		return Record{}, false, err
	}

	data, err := s.kv.Read(ctx, path)
	if errors.Is(err, secrets.ErrKVNotFound) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}

	str := func(field string) (string, error) {
		switch v := data[field].(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			return "", fmt.Errorf("pxestate: field %s is not a string", field)
		}
	}
	fields := make(map[string]string, 5)
	for _, f := range []string{"image", "version", "sha256", "provisioned_at", "method"} {
		v, err := str(f)
		if err != nil {
			return Record{}, false, err
		}
		fields[f] = v
	}

	rec = Record{
		Image:   fields["image"],
		Version: fields["version"],
		SHA256:  fields["sha256"],
		Method:  fields["method"],
	}
	if ts := fields["provisioned_at"]; ts != "" {
		rec.ProvisionedAt, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return Record{}, false, fmt.Errorf("pxestate: parse provisioned_at: %w", err)
		}
	}
	return rec, true, nil
}

// Put stores rec as the record for uuid. ProvisionedAt is stored in UTC as
// RFC 3339.
func (s *Store) Put(ctx context.Context, uuid string, rec Record) error {
	path, err := s.path(uuid)
	if err != nil {
		return err
	}
	data := map[string]string{
		"image":   rec.Image,
		"version": rec.Version,
		"sha256":  rec.SHA256,
		"method":  rec.Method,
	}
	if !rec.ProvisionedAt.IsZero() {
		data["provisioned_at"] = rec.ProvisionedAt.UTC().Format(time.RFC3339)
	}
	return s.kv.Write(ctx, path, data)
}
