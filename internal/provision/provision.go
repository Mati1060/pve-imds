// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package provision decides whether a machine should be provisioned and with
// what, and validates what the provisioning live OS reports back. It takes
// plain inputs (the desired state, the recorded state and the manifest) and
// knows nothing about how a machine was identified, so services other than
// the per-VM IMDS handlers can use it.
//
// Two image types exist. A disk image is a raw.zst image that a live OS
// fetches (see [Provisioner.Job]) and writes to disk, then reports with
// [Provisioner.Done]. A chain image is a remote iPXE target; with boot
// "once" it is chained until a state record exists for it, with boot
// "always" on every boot.
//
// Every failure fails closed: the machine boots from disk.
package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wyattanderson/pve-imds/internal/pxestate"
	"github.com/wyattanderson/pve-imds/pkg/manifest"
)

// Outcomes of a decision, logged as "outcome".
const (
	OutcomeManifestError    = "manifest_error"
	OutcomeManifestMiss     = "manifest_miss"
	OutcomeStateError       = "state_error"
	OutcomeProvisionNew     = "provision_new"
	OutcomeProvisionChanged = "provision_changed"
	OutcomeProvisioned      = "provisioned"
	OutcomeLiveUKIMissing   = "live_uki_missing"
	OutcomeChainOnce        = "chain_once"
	OutcomeChainAlways      = "chain_always"
	OutcomeChainNotAllowed  = "chain_not_allowed"
	OutcomeImageURLError    = "image_url_error"
)

// Outcomes of [Provisioner.Done].
const (
	OutcomeDone          = "done"
	OutcomeDoneUnchanged = "done_unchanged"
	OutcomeDoneMismatch  = "done_mismatch"
)

// Methods stored in a state record.
const (
	MethodDisk  = "disk"
	MethodChain = "chain"
)

// ExitScript makes iPXE return to the firmware, which boots the next device.
const ExitScript = "#!ipxe\nexit\n"

var (
	// ErrMismatch is returned by [Provisioner.Done] when the report does not
	// match the desired state or the manifest.
	ErrMismatch = errors.New("provision: report does not match")

	// ErrUnavailable is returned by [Provisioner.Done] when the manifest or
	// the state store cannot be reached; the caller should retry.
	ErrUnavailable = errors.New("provision: temporarily unavailable")
)

// Desired is the provisioning state a machine should be in.
type Desired struct {
	Image string
	// Version is empty when unpinned: the latest version is installed once
	// and never replaced because latest moved.
	Version string
	// Disk is the device path a disk image is written to.
	Disk string
}

// StateStore reads and writes state records. *pxestate.Store implements it.
type StateStore interface {
	Get(ctx context.Context, uuid string) (rec pxestate.Record, found bool, err error)
	Put(ctx context.Context, uuid string, rec pxestate.Record) error
}

// ImageBucket hands out access to disk images in a private bucket.
// *s3.Bucket implements it.
type ImageBucket interface {
	// PresignGet returns a short-lived URL for the object at rawURL.
	PresignGet(ctx context.Context, rawURL string) (string, error)
}

// Options configures a [Provisioner].
type Options struct {
	Manifests ManifestSource
	State     StateStore
	// Images, if non-nil, presigns the URL of every disk image job. Nil
	// hands out the manifest URL as it is.
	Images ImageBucket
	// LiveUKI is the path of the live OS UKI. A disk image is only
	// provisioned while it is readable.
	LiveUKI string
	// LiveUKIURL is what iPXE chains to boot the live OS, typically a path
	// relative to the script's URL.
	LiveUKIURL string
	// ChainAllowedPrefixes are re-checked when a chain image is chained.
	ChainAllowedPrefixes []string
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Provisioner makes provisioning decisions.
type Provisioner struct {
	opts Options
	now  func() time.Time
}

// New returns a Provisioner.
func New(opts Options) *Provisioner {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Provisioner{opts: opts, now: now}
}

// Plan is a decision without side effects.
type Plan struct {
	Outcome string
	// Err explains a failure outcome; it is nil otherwise.
	Err error
	// Provision is true when the machine should be provisioned now.
	Provision bool

	// Image and Version are the resolved image; Version is the manifest
	// version, also when the desired state is unpinned. They are empty when
	// resolution failed.
	Image   string
	Version string
	Type    ImageType
	Boot    BootMode
	Entry   Version
}

// IsDiskProvision reports whether the plan provisions a disk image, which
// is when the live OS may boot and fetch its job.
func (p Plan) IsDiskProvision() bool {
	return p.Provision && p.Type == TypeDisk
}

// resolve looks up the desired image and version (or latest) in the
// manifest.
func (p *Provisioner) resolve(ctx context.Context, d Desired) Plan {
	m, err := p.opts.Manifests.Manifest(ctx)
	if err != nil {
		return Plan{Outcome: OutcomeManifestError, Err: err}
	}
	img, ok := m.Images[d.Image]
	if !ok {
		return Plan{Outcome: OutcomeManifestMiss, Err: fmt.Errorf("image %q is not in the manifest", d.Image)}
	}
	version := d.Version
	if version == "" {
		version = img.Latest
	}
	entry, ok := img.Versions[version]
	if !ok {
		return Plan{Outcome: OutcomeManifestMiss, Err: fmt.Errorf("version %q of image %q is not in the manifest", version, d.Image)}
	}
	return Plan{Image: d.Image, Version: version, Type: img.Type, Boot: img.Boot, Entry: entry}
}

// Plan decides what uuid's machine should do, without side effects:
//
//	manifest fetch fails                       → manifest_error
//	image or version not in the manifest       → manifest_miss
//	chain image with boot "always"             → chain_always (no state read)
//	state read fails                           → state_error
//	no record                                  → provision_new (chain_once for chain images)
//	record image differs                       → provision_changed (chain_once)
//	pinned version differs from the record     → provision_changed (chain_once)
//	otherwise                                  → provisioned
func (p *Provisioner) Plan(ctx context.Context, uuid string, d Desired) Plan {
	plan := p.resolve(ctx, d)
	if plan.Outcome != "" {
		return plan
	}

	if plan.Type == TypeChain && plan.Boot == BootAlways {
		plan.Outcome, plan.Provision = OutcomeChainAlways, true
		return plan
	}

	rec, found, err := p.opts.State.Get(ctx, uuid)
	switch {
	case err != nil:
		plan.Outcome, plan.Err = OutcomeStateError, err
		return plan
	case !found:
		plan.Outcome = OutcomeProvisionNew
	case rec.Image != d.Image:
		plan.Outcome = OutcomeProvisionChanged
	case d.Version != "" && d.Version != rec.Version:
		plan.Outcome = OutcomeProvisionChanged
	default:
		plan.Outcome = OutcomeProvisioned
		return plan
	}
	plan.Provision = true
	if plan.Type == TypeChain {
		plan.Outcome = OutcomeChainOnce
	}
	return plan
}

// Boot makes the decision for one boot and returns it with the iPXE script
// to serve. A chain image with boot "once" is recorded as provisioned
// before its script is returned. Every failure returns [ExitScript].
func (p *Provisioner) Boot(ctx context.Context, uuid string, d Desired) (Plan, string) {
	plan := p.Plan(ctx, uuid, d)
	if !plan.Provision {
		return plan, ExitScript
	}

	switch plan.Type {
	case TypeDisk:
		if err := checkReadable(p.opts.LiveUKI); err != nil {
			plan.Outcome, plan.Err, plan.Provision = OutcomeLiveUKIMissing, err, false
			return plan, ExitScript
		}
		return plan, "#!ipxe\nchain " + p.opts.LiveUKIURL + "\n"

	default:
		if err := manifest.CheckChainURL(plan.Entry.URL, p.opts.ChainAllowedPrefixes); err != nil {
			plan.Outcome, plan.Err, plan.Provision = OutcomeChainNotAllowed, err, false
			return plan, ExitScript
		}
		if plan.Boot == BootOnce {
			err := p.opts.State.Put(ctx, uuid, pxestate.Record{
				Image:         plan.Image,
				Version:       plan.Version,
				ProvisionedAt: p.now(),
				Method:        MethodChain,
			})
			if err != nil {
				plan.Outcome, plan.Err, plan.Provision = OutcomeStateError, err, false
				return plan, ExitScript
			}
		}
		return plan, "#!ipxe\nchain " + plan.Entry.URL + "\n"
	}
}

// checkReadable returns an error unless path is a regular file that can be
// opened for reading.
func checkReadable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

// Job is what the live OS installs.
type Job struct {
	Image   string `json:"image"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Disk    string `json:"disk"`
}

// Job returns the disk image job for uuid's machine, resolved now. ok is
// false unless the plan provisions a disk image; plan says why. With
// [Options.Images] set, URL is presigned for this request only, so a live
// OS that retries a download should fetch its job again; the URL must not
// be logged.
func (p *Provisioner) Job(ctx context.Context, uuid string, d Desired) (job Job, plan Plan, ok bool) {
	plan = p.Plan(ctx, uuid, d)
	if !plan.IsDiskProvision() {
		return Job{}, plan, false
	}
	url := plan.Entry.URL
	if p.opts.Images != nil {
		signed, err := p.opts.Images.PresignGet(ctx, url)
		if err != nil {
			plan.Outcome, plan.Err, plan.Provision = OutcomeImageURLError, err, false
			return Job{}, plan, false
		}
		url = signed
	}
	return Job{
		Image:   plan.Image,
		Version: plan.Version,
		URL:     url,
		SHA256:  plan.Entry.SHA256,
		Size:    plan.Entry.Size,
		Disk:    d.Disk,
	}, plan, true
}

// DoneReport is what the live OS reports after writing a disk image.
type DoneReport struct {
	Image   string `json:"image"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Done validates a report and records the machine as provisioned. No job
// state is kept, so the report is checked against the desired state and the
// manifest as they are now:
//
//   - image must equal the desired image
//   - version must equal the desired version when it is pinned
//   - version must exist in the manifest for a disk image, and sha256 must
//     match it
//
// A mismatch returns an error wrapping [ErrMismatch]; an unreachable
// manifest or state store one wrapping [ErrUnavailable]. A report identical
// to the existing record is accepted without writing.
func (p *Provisioner) Done(ctx context.Context, uuid string, d Desired, r DoneReport) (string, error) {
	mismatch := func(format string, args ...any) (string, error) {
		return OutcomeDoneMismatch, fmt.Errorf("%w: %s", ErrMismatch, fmt.Sprintf(format, args...))
	}

	if r.Image != d.Image {
		return mismatch("image %q is not the desired image %q", r.Image, d.Image)
	}
	if d.Version != "" && r.Version != d.Version {
		return mismatch("version %q is not the pinned version %q", r.Version, d.Version)
	}

	m, err := p.opts.Manifests.Manifest(ctx)
	if err != nil {
		return OutcomeManifestError, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	img, ok := m.Images[r.Image]
	if !ok || img.Type != TypeDisk {
		return mismatch("image %q is not a disk image in the manifest", r.Image)
	}
	entry, ok := img.Versions[r.Version]
	if !ok {
		return mismatch("version %q of image %q is not in the manifest", r.Version, r.Image)
	}
	if !strings.EqualFold(r.SHA256, entry.SHA256) {
		return mismatch("sha256 does not match the manifest")
	}

	rec, found, err := p.opts.State.Get(ctx, uuid)
	if err != nil {
		return OutcomeStateError, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if found && rec.Method == MethodDisk && rec.Image == r.Image && rec.Version == r.Version && rec.SHA256 == entry.SHA256 {
		return OutcomeDoneUnchanged, nil
	}

	err = p.opts.State.Put(ctx, uuid, pxestate.Record{
		Image:         r.Image,
		Version:       r.Version,
		SHA256:        entry.SHA256,
		ProvisionedAt: p.now(),
		Method:        MethodDisk,
	})
	if err != nil {
		return OutcomeStateError, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return OutcomeDone, nil
}
