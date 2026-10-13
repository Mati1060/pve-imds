package provision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/pxestate"
)

const (
	testUUID = "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81"
	testDisk = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0"
	shaOld   = "0000000000000000000000000000000000000000000000000000000000000001"
	debURL   = "https://rgw.example.com/pxe/debian13/2026.10.01.raw.zst"
)

var testNow = time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC)

func testManifest() *Manifest {
	return &Manifest{Images: map[string]Image{
		"debian13": {
			Type:   TypeDisk,
			Latest: "2026.10.01",
			Versions: map[string]Version{
				"2026.10.01": {URL: debURL, SHA256: sha, Size: 123},
				"2026.09.01": {URL: "https://rgw.example.com/pxe/debian13/2026.09.01.raw.zst", SHA256: shaOld, Size: 100},
			},
		},
		"talos": {
			Type:     TypeChain,
			Boot:     BootOnce,
			Latest:   "v1.14.2",
			Versions: map[string]Version{"v1.14.2": {URL: talosURL}, "v1.14.1": {URL: talosPrefix + "s/v1.14.1/x"}},
		},
		"rescue": {
			Type:     TypeChain,
			Boot:     BootAlways,
			Latest:   "1",
			Versions: map[string]Version{"1": {URL: talosPrefix + "rescue"}},
		},
	}}
}

type fakeManifests struct {
	m   *Manifest
	err error
}

func (f fakeManifests) Manifest(context.Context) (*Manifest, error) { return f.m, f.err }

type fakeStore struct {
	rec    *pxestate.Record
	getErr error
	putErr error
	gets   int
	puts   []pxestate.Record
}

func (f *fakeStore) Get(_ context.Context, uuid string) (pxestate.Record, bool, error) {
	f.gets++
	if uuid != testUUID {
		return pxestate.Record{}, false, errors.New("unexpected uuid " + uuid)
	}
	if f.getErr != nil {
		return pxestate.Record{}, false, f.getErr
	}
	if f.rec == nil {
		return pxestate.Record{}, false, nil
	}
	return *f.rec, true, nil
}

func (f *fakeStore) Put(_ context.Context, uuid string, rec pxestate.Record) error {
	if uuid != testUUID {
		return errors.New("unexpected uuid " + uuid)
	}
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, rec)
	r := rec
	f.rec = &r
	return nil
}

func liveUKI(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "live.efi")
	require.NoError(t, os.WriteFile(p, []byte("MZ..."), 0o600))
	return p
}

func newProvisioner(t *testing.T, mf ManifestSource, st StateStore, uki string) *Provisioner {
	t.Helper()
	return New(Options{
		Manifests:            mf,
		State:                st,
		LiveUKI:              uki,
		LiveUKIURL:           "/pxe/live.efi",
		ChainAllowedPrefixes: allowed,
		Now:                  func() time.Time { return testNow },
	})
}

func rec(image, version string) *pxestate.Record {
	return &pxestate.Record{Image: image, Version: version}
}

func TestBootDecisionTable(t *testing.T) {
	const liveScript = "#!ipxe\nchain /pxe/live.efi\n"

	cases := []struct {
		name        string
		desired     Desired
		manifestErr error
		state       *pxestate.Record
		getErr      error
		putErr      error
		noUKI       bool
		prefixes    []string // overrides the allowlist at decision time
		wantOutcome string
		wantScript  string
		wantVersion string
		wantPut     *pxestate.Record
		wantGets    int
	}{
		{
			name:        "manifest fetch fails",
			desired:     Desired{Image: "debian13"},
			manifestErr: errors.New("connection refused"),
			wantOutcome: OutcomeManifestError,
			wantScript:  ExitScript,
		},
		{
			name:        "unknown image",
			desired:     Desired{Image: "arch"},
			wantOutcome: OutcomeManifestMiss,
			wantScript:  ExitScript,
		},
		{
			name:        "unknown pinned version",
			desired:     Desired{Image: "debian13", Version: "2020.01.01"},
			wantOutcome: OutcomeManifestMiss,
			wantScript:  ExitScript,
		},
		{
			name:        "state read fails",
			desired:     Desired{Image: "debian13"},
			getErr:      errors.New("403"),
			wantOutcome: OutcomeStateError,
			wantScript:  ExitScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "disk, no record, unpinned → latest",
			desired:     Desired{Image: "debian13"},
			wantOutcome: OutcomeProvisionNew,
			wantScript:  liveScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "disk, no record, pinned",
			desired:     Desired{Image: "debian13", Version: "2026.09.01"},
			wantOutcome: OutcomeProvisionNew,
			wantScript:  liveScript,
			wantVersion: "2026.09.01",
			wantGets:    1,
		},
		{
			name:        "disk, image changed",
			desired:     Desired{Image: "debian13"},
			state:       rec("talos", "v1.14.2"),
			wantOutcome: OutcomeProvisionChanged,
			wantScript:  liveScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "disk, pinned version changed",
			desired:     Desired{Image: "debian13", Version: "2026.10.01"},
			state:       rec("debian13", "2026.09.01"),
			wantOutcome: OutcomeProvisionChanged,
			wantScript:  liveScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "disk, pinned version matches",
			desired:     Desired{Image: "debian13", Version: "2026.09.01"},
			state:       rec("debian13", "2026.09.01"),
			wantOutcome: OutcomeProvisioned,
			wantScript:  ExitScript,
			wantVersion: "2026.09.01",
			wantGets:    1,
		},
		{
			name:        "disk, unpinned never reprovisions because latest moved",
			desired:     Desired{Image: "debian13"},
			state:       rec("debian13", "2026.09.01"),
			wantOutcome: OutcomeProvisioned,
			wantScript:  ExitScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "disk, live UKI missing",
			desired:     Desired{Image: "debian13"},
			noUKI:       true,
			wantOutcome: OutcomeLiveUKIMissing,
			wantScript:  ExitScript,
			wantVersion: "2026.10.01",
			wantGets:    1,
		},
		{
			name:        "chain once, no record → record then chain",
			desired:     Desired{Image: "talos"},
			wantOutcome: OutcomeChainOnce,
			wantScript:  "#!ipxe\nchain " + talosURL + "\n",
			wantVersion: "v1.14.2",
			wantPut:     &pxestate.Record{Image: "talos", Version: "v1.14.2", ProvisionedAt: testNow, Method: MethodChain},
			wantGets:    1,
		},
		{
			name:        "chain once, pinned version changed",
			desired:     Desired{Image: "talos", Version: "v1.14.2"},
			state:       rec("talos", "v1.14.1"),
			wantOutcome: OutcomeChainOnce,
			wantScript:  "#!ipxe\nchain " + talosURL + "\n",
			wantVersion: "v1.14.2",
			wantPut:     &pxestate.Record{Image: "talos", Version: "v1.14.2", ProvisionedAt: testNow, Method: MethodChain},
			wantGets:    1,
		},
		{
			name:        "chain once, already chained",
			desired:     Desired{Image: "talos"},
			state:       rec("talos", "v1.14.1"),
			wantOutcome: OutcomeProvisioned,
			wantScript:  ExitScript,
			wantVersion: "v1.14.2",
			wantGets:    1,
		},
		{
			name:        "chain once, state write fails",
			desired:     Desired{Image: "talos"},
			putErr:      errors.New("403"),
			wantOutcome: OutcomeStateError,
			wantScript:  ExitScript,
			wantVersion: "v1.14.2",
			wantGets:    1,
		},
		{
			name:        "chain once, url no longer allowed",
			desired:     Desired{Image: "talos"},
			prefixes:    []string{"https://boot.example.com/"},
			wantOutcome: OutcomeChainNotAllowed,
			wantScript:  ExitScript,
			wantVersion: "v1.14.2",
			wantGets:    1,
		},
		{
			name:        "chain always ignores state",
			desired:     Desired{Image: "rescue"},
			state:       rec("rescue", "1"),
			getErr:      errors.New("never read"),
			wantOutcome: OutcomeChainAlways,
			wantScript:  "#!ipxe\nchain " + talosPrefix + "rescue\n",
			wantVersion: "1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{rec: tc.state, getErr: tc.getErr, putErr: tc.putErr}
			uki := liveUKI(t)
			if tc.noUKI {
				uki = filepath.Join(t.TempDir(), "missing.efi")
			}
			p := newProvisioner(t, fakeManifests{m: testManifest(), err: tc.manifestErr}, st, uki)
			if tc.prefixes != nil {
				p.opts.ChainAllowedPrefixes = tc.prefixes
			}

			plan, script := p.Boot(context.Background(), testUUID, tc.desired)
			assert.Equal(t, tc.wantOutcome, plan.Outcome)
			assert.Equal(t, tc.wantScript, script)
			assert.Equal(t, tc.wantVersion, plan.Version)
			assert.Equal(t, tc.wantGets, st.gets)
			if tc.wantPut != nil {
				assert.Equal(t, []pxestate.Record{*tc.wantPut}, st.puts)
			} else {
				assert.Empty(t, st.puts)
			}
			if script == ExitScript && tc.wantOutcome != OutcomeProvisioned {
				assert.Error(t, plan.Err, "failure outcomes carry the reason")
			}
		})
	}
}

func TestPlanHasNoSideEffects(t *testing.T) {
	st := &fakeStore{}
	p := newProvisioner(t, fakeManifests{m: testManifest()}, st, filepath.Join(t.TempDir(), "missing.efi"))

	plan := p.Plan(context.Background(), testUUID, Desired{Image: "talos"})
	assert.Equal(t, OutcomeChainOnce, plan.Outcome)
	assert.Empty(t, st.puts, "Plan never writes state")

	plan = p.Plan(context.Background(), testUUID, Desired{Image: "debian13"})
	assert.True(t, plan.IsDiskProvision(), "Plan does not check the live UKI")
}

func TestJob(t *testing.T) {
	p := newProvisioner(t, fakeManifests{m: testManifest()}, &fakeStore{}, liveUKI(t))

	job, plan, ok := p.Job(context.Background(), testUUID, Desired{Image: "debian13", Disk: testDisk})
	require.True(t, ok)
	assert.Equal(t, OutcomeProvisionNew, plan.Outcome)
	assert.Equal(t, Job{Image: "debian13", Version: "2026.10.01", URL: debURL, SHA256: sha, Size: 123, Disk: testDisk}, job)

	for name, tc := range map[string]struct {
		desired Desired
		state   *pxestate.Record
	}{
		"already provisioned": {Desired{Image: "debian13"}, rec("debian13", "2026.09.01")},
		"chain image":         {Desired{Image: "talos"}, nil},
		"unknown image":       {Desired{Image: "arch"}, nil},
	} {
		p := newProvisioner(t, fakeManifests{m: testManifest()}, &fakeStore{rec: tc.state}, liveUKI(t))
		_, _, ok := p.Job(context.Background(), testUUID, tc.desired)
		assert.False(t, ok, name)
	}
}

func TestDone(t *testing.T) {
	want := pxestate.Record{Image: "debian13", Version: "2026.10.01", SHA256: sha, ProvisionedAt: testNow, Method: MethodDisk}

	cases := []struct {
		name        string
		desired     Desired
		report      DoneReport
		state       *pxestate.Record
		manifestErr error
		getErr      error
		putErr      error
		wantOutcome string
		wantErr     error
		wantPut     bool
	}{
		{
			name:        "unpinned, latest",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			wantOutcome: OutcomeDone,
			wantPut:     true,
		},
		{
			name:        "uppercase sha256 is accepted",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: strings.ToUpper(sha)},
			wantOutcome: OutcomeDone,
			wantPut:     true,
		},
		{
			name:        "pinned",
			desired:     Desired{Image: "debian13", Version: "2026.10.01"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			state:       rec("debian13", "2026.09.01"),
			wantOutcome: OutcomeDone,
			wantPut:     true,
		},
		{
			name:        "repeated identical done",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			state:       &want,
			wantOutcome: OutcomeDoneUnchanged,
		},
		{
			name:        "wrong image",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian12", Version: "2026.10.01", SHA256: sha},
			wantOutcome: OutcomeDoneMismatch,
			wantErr:     ErrMismatch,
		},
		{
			name:        "version differs from pin",
			desired:     Desired{Image: "debian13", Version: "2026.09.01"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			wantOutcome: OutcomeDoneMismatch,
			wantErr:     ErrMismatch,
		},
		{
			name:        "version not in manifest",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2020.01.01", SHA256: sha},
			wantOutcome: OutcomeDoneMismatch,
			wantErr:     ErrMismatch,
		},
		{
			name:        "wrong sha256",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: shaOld},
			wantOutcome: OutcomeDoneMismatch,
			wantErr:     ErrMismatch,
		},
		{
			name:        "chain image",
			desired:     Desired{Image: "talos"},
			report:      DoneReport{Image: "talos", Version: "v1.14.2"},
			wantOutcome: OutcomeDoneMismatch,
			wantErr:     ErrMismatch,
		},
		{
			name:        "manifest unavailable",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			manifestErr: errors.New("timeout"),
			wantOutcome: OutcomeManifestError,
			wantErr:     ErrUnavailable,
		},
		{
			name:        "state read fails",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			getErr:      errors.New("500"),
			wantOutcome: OutcomeStateError,
			wantErr:     ErrUnavailable,
		},
		{
			name:        "state write fails",
			desired:     Desired{Image: "debian13"},
			report:      DoneReport{Image: "debian13", Version: "2026.10.01", SHA256: sha},
			putErr:      errors.New("403"),
			wantOutcome: OutcomeStateError,
			wantErr:     ErrUnavailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStore{rec: tc.state, getErr: tc.getErr, putErr: tc.putErr}
			p := newProvisioner(t, fakeManifests{m: testManifest(), err: tc.manifestErr}, st, liveUKI(t))

			outcome, err := p.Done(context.Background(), testUUID, tc.desired, tc.report)
			assert.Equal(t, tc.wantOutcome, outcome)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tc.wantPut {
				assert.Equal(t, []pxestate.Record{want}, st.puts)
			} else {
				assert.Empty(t, st.puts)
			}
		})
	}
}

func TestDoneThenBootExits(t *testing.T) {
	st := &fakeStore{}
	p := newProvisioner(t, fakeManifests{m: testManifest()}, st, liveUKI(t))
	ctx := context.Background()
	d := Desired{Image: "debian13", Disk: testDisk}

	job, _, ok := p.Job(ctx, testUUID, d)
	require.True(t, ok)
	_, err := p.Done(ctx, testUUID, d, DoneReport{Image: job.Image, Version: job.Version, SHA256: job.SHA256})
	require.NoError(t, err)

	plan, script := p.Boot(ctx, testUUID, d)
	assert.Equal(t, OutcomeProvisioned, plan.Outcome)
	assert.Equal(t, ExitScript, script)
}
