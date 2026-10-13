package pxe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/provision"
	"github.com/wyattanderson/pve-imds/internal/pxestate"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

const (
	testUUID = "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81"
	sha      = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
	debURL   = "https://rgw.example.com/pxe/debian13/2026.10.01.raw.zst"
	talosURL = "https://pxe.factory.talos.dev/pxe/abc/v1.14.2/nocloud-amd64-secureboot"

	debianBlock = "<!--#pxe\nimage: debian13\n-->"
	talosBlock  = "<!--#pxe\nimage: talos\n-->"
)

var testNow = time.Date(2026, 10, 13, 18, 0, 0, 0, time.UTC)

type fakeResolver struct {
	rec *identity.VMRecord
	err error
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, f.err
}

type fakeManifests struct{ err error }

func (f fakeManifests) Manifest(context.Context) (*provision.Manifest, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &provision.Manifest{Images: map[string]provision.Image{
		"debian13": {
			Type:     provision.TypeDisk,
			Latest:   "2026.10.01",
			Versions: map[string]provision.Version{"2026.10.01": {URL: debURL, SHA256: sha, Size: 42}},
		},
		"talos": {
			Type:     provision.TypeChain,
			Boot:     provision.BootOnce,
			Latest:   "v1.14.2",
			Versions: map[string]provision.Version{"v1.14.2": {URL: talosURL}},
		},
	}}, nil
}

type fakeState struct {
	rec    *pxestate.Record
	getErr error
	putErr error
	puts   []pxestate.Record
}

func (f *fakeState) Get(_ context.Context, uuid string) (pxestate.Record, bool, error) {
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

func (f *fakeState) Put(_ context.Context, _ string, rec pxestate.Record) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, rec)
	r := rec
	f.rec = &r
	return nil
}

func testRecord(smbiosUUID, notes string) *identity.VMRecord {
	smbios := map[string]string{}
	if smbiosUUID != "" {
		smbios["uuid"] = smbiosUUID
	}
	return &identity.VMRecord{
		Node: "pve-node1",
		VMID: 500,
		Config: &vmconfig.VMConfig{
			Name:        "web-1",
			Description: notes,
			SMBIOS:      smbios,
		},
	}
}

// env is a mux with the PXE endpoints for one VM.
type env struct {
	mux     *http.ServeMux
	logs    *bytes.Buffer
	state   *fakeState
	liveUKI string
}

type envOpts struct {
	rec         *identity.VMRecord
	resolverErr error
	state       *pxestate.Record
	getErr      error
	putErr      error
	manifestErr error
	noUKI       bool
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	e := &env{logs: &bytes.Buffer{}, state: &fakeState{rec: o.state, getErr: o.getErr, putErr: o.putErr}}
	e.liveUKI = filepath.Join(t.TempDir(), "live.efi")
	if !o.noUKI {
		require.NoError(t, os.WriteFile(e.liveUKI, []byte("MZ live uki"), 0o600))
	}
	log := slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prov := provision.New(provision.Options{
		Manifests:            fakeManifests{err: o.manifestErr},
		State:                e.state,
		LiveUKI:              e.liveUKI,
		LiveUKIURL:           LiveUKIPath,
		ChainAllowedPrefixes: []string{"https://pxe.factory.talos.dev/pxe/"},
		Now:                  func() time.Time { return testNow },
	})
	e.mux = http.NewServeMux()
	NewServer(log, prov, e.liveUKI).Register(e.mux, &fakeResolver{rec: o.rec, err: o.resolverErr}, "tap500i0", 7)
	return e
}

func (e *env) do(t *testing.T, method, path, body string) (*http.Response, string) {
	t.Helper()
	e.logs.Reset()
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	resp := w.Result()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(b)
}

// infoLines returns the info log lines of the last request.
func (e *env) infoLines() []map[string]any {
	var out []map[string]any
	for l := range strings.SplitSeq(strings.TrimSpace(e.logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["level"] == "INFO" {
			out = append(out, m)
		}
	}
	return out
}

func (e *env) warned() bool {
	return strings.Contains(e.logs.String(), `"level":"WARN"`)
}

// assertOneInfo checks the one info line of the last request.
func assertOneInfo(t *testing.T, e *env, outcome string) map[string]any {
	t.Helper()
	lines := e.infoLines()
	require.Len(t, lines, 1, "exactly one info line per request")
	for _, k := range []string{"vmid", "uuid", "image", "version", "outcome"} {
		assert.Contains(t, lines[0], k)
	}
	assert.Equal(t, outcome, lines[0]["outcome"])
	return lines[0]
}

func TestBoot(t *testing.T) {
	cases := []struct {
		name        string
		opts        envOpts
		wantBody    string
		wantOutcome string
		wantWarn    bool
	}{
		{
			name:        "identity lookup fails",
			opts:        envOpts{resolverErr: errors.New("no such interface")},
			wantBody:    provision.ExitScript,
			wantOutcome: OutcomeNoIdentity,
			wantWarn:    true,
		},
		{
			name:        "no smbios uuid",
			opts:        envOpts{rec: testRecord("", debianBlock)},
			wantBody:    provision.ExitScript,
			wantOutcome: OutcomeNoUUID,
			wantWarn:    true,
		},
		{
			name:        "no pxe block",
			opts:        envOpts{rec: testRecord(testUUID, "just notes")},
			wantBody:    provision.ExitScript,
			wantOutcome: OutcomeNoBlock,
		},
		{
			name:        "invalid pxe block",
			opts:        envOpts{rec: testRecord(testUUID, "<!--#pxe\nimage: Debian13\n-->")},
			wantBody:    provision.ExitScript,
			wantOutcome: OutcomeNoBlock,
			wantWarn:    true,
		},
		{
			name:        "manifest error",
			opts:        envOpts{rec: testRecord(testUUID, debianBlock), manifestErr: errors.New("timeout")},
			wantBody:    provision.ExitScript,
			wantOutcome: provision.OutcomeManifestError,
			wantWarn:    true,
		},
		{
			name:        "manifest miss",
			opts:        envOpts{rec: testRecord(testUUID, "<!--#pxe\nimage: arch\n-->")},
			wantBody:    provision.ExitScript,
			wantOutcome: provision.OutcomeManifestMiss,
			wantWarn:    true,
		},
		{
			name:        "state error",
			opts:        envOpts{rec: testRecord(testUUID, debianBlock), getErr: errors.New("403")},
			wantBody:    provision.ExitScript,
			wantOutcome: provision.OutcomeStateError,
			wantWarn:    true,
		},
		{
			name:        "disk provision",
			opts:        envOpts{rec: testRecord(testUUID, debianBlock)},
			wantBody:    "#!ipxe\nchain /pxe/live.efi\n",
			wantOutcome: provision.OutcomeProvisionNew,
		},
		{
			name:        "disk provision without live UKI",
			opts:        envOpts{rec: testRecord(testUUID, debianBlock), noUKI: true},
			wantBody:    provision.ExitScript,
			wantOutcome: provision.OutcomeLiveUKIMissing,
			wantWarn:    true,
		},
		{
			name:        "chain once",
			opts:        envOpts{rec: testRecord(testUUID, talosBlock)},
			wantBody:    "#!ipxe\nchain " + talosURL + "\n",
			wantOutcome: provision.OutcomeChainOnce,
		},
		{
			name:        "already provisioned",
			opts:        envOpts{rec: testRecord(testUUID, debianBlock), state: &pxestate.Record{Image: "debian13", Version: "2026.09.01"}},
			wantBody:    provision.ExitScript,
			wantOutcome: provision.OutcomeProvisioned,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			resp, body := e.do(t, http.MethodGet, Path, "")

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
			assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
			assert.True(t, strings.HasPrefix(body, "#!ipxe\n"))
			assert.Equal(t, tc.wantBody, body)
			assertOneInfo(t, e, tc.wantOutcome)
			assert.Equal(t, tc.wantWarn, e.warned())
		})
	}
}

func TestBootLogFields(t *testing.T) {
	e := newEnv(t, envOpts{rec: testRecord(strings.ToUpper(testUUID), debianBlock)})
	e.do(t, http.MethodGet, Path, "")
	line := assertOneInfo(t, e, provision.OutcomeProvisionNew)
	assert.InDelta(t, 500, line["vmid"], 0)
	assert.Equal(t, testUUID, line["uuid"], "uuid is logged lowercased")
	assert.Equal(t, "debian13", line["image"])
	assert.Equal(t, "2026.10.01", line["version"], "the resolved version is logged")
}

func TestLiveUKIGating(t *testing.T) {
	cases := []struct {
		name        string
		opts        envOpts
		wantStatus  int
		wantOutcome string
	}{
		{"disk provision", envOpts{rec: testRecord(testUUID, debianBlock)}, http.StatusOK, provision.OutcomeProvisionNew},
		{"already provisioned", envOpts{rec: testRecord(testUUID, debianBlock), state: &pxestate.Record{Image: "debian13", Version: "x"}}, http.StatusNotFound, provision.OutcomeProvisioned},
		{"chain image", envOpts{rec: testRecord(testUUID, talosBlock)}, http.StatusNotFound, provision.OutcomeChainOnce},
		{"no block", envOpts{rec: testRecord(testUUID, "")}, http.StatusNotFound, OutcomeNoBlock},
		{"no identity", envOpts{resolverErr: errors.New("x")}, http.StatusNotFound, OutcomeNoIdentity},
		{"state error", envOpts{rec: testRecord(testUUID, debianBlock), getErr: errors.New("x")}, http.StatusNotFound, provision.OutcomeStateError},
		{"live UKI missing", envOpts{rec: testRecord(testUUID, debianBlock), noUKI: true}, http.StatusNotFound, provision.OutcomeLiveUKIMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			resp, body := e.do(t, http.MethodGet, LiveUKIPath, "")
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			line := assertOneInfo(t, e, tc.wantOutcome)
			assert.Contains(t, line, "bytes")
			assert.Contains(t, line, "duration")
			if tc.wantStatus == http.StatusOK {
				assert.Equal(t, "MZ live uki", body)
				assert.Equal(t, "application/octet-stream", resp.Header.Get("Content-Type"))
				assert.Equal(t, "11", resp.Header.Get("Content-Length"))
				assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
				assert.InDelta(t, 11, line["bytes"], 0)
			}
			assert.Empty(t, e.state.puts, "live.efi never writes state")
		})
	}
}

func TestLiveUKIIsReadPerRequest(t *testing.T) {
	e := newEnv(t, envOpts{rec: testRecord(testUUID, debianBlock)})
	_, body := e.do(t, http.MethodGet, LiveUKIPath, "")
	assert.Equal(t, "MZ live uki", body)

	require.NoError(t, os.WriteFile(e.liveUKI, []byte("MZ new"), 0o600))
	_, body = e.do(t, http.MethodGet, LiveUKIPath, "")
	assert.Equal(t, "MZ new", body)
}

func TestJob(t *testing.T) {
	e := newEnv(t, envOpts{rec: testRecord(testUUID, "<!--#pxe\nimage: debian13\ndisk: /dev/disk/by-id/virtio-root\n-->")})
	resp, body := e.do(t, http.MethodGet, JobPath, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.JSONEq(t, `{"image":"debian13","version":"2026.10.01","url":"`+debURL+`","sha256":"`+sha+`","size":42,"disk":"/dev/disk/by-id/virtio-root"}`, body)
	assertOneInfo(t, e, provision.OutcomeProvisionNew)

	for name, o := range map[string]envOpts{
		"already provisioned": {rec: testRecord(testUUID, debianBlock), state: &pxestate.Record{Image: "debian13", Version: "x"}},
		"chain image":         {rec: testRecord(testUUID, talosBlock)},
		"no block":            {rec: testRecord(testUUID, "")},
		"no identity":         {resolverErr: errors.New("x")},
	} {
		e := newEnv(t, o)
		resp, body := e.do(t, http.MethodGet, JobPath, "")
		assert.Equal(t, http.StatusConflict, resp.StatusCode, name)
		var je jsonError
		require.NoError(t, json.Unmarshal([]byte(body), &je), name)
		assert.NotEmpty(t, je.Outcome, name)
		assert.Len(t, e.infoLines(), 1, name)
	}
}

func TestDone(t *testing.T) {
	good := `{"image":"debian13","version":"2026.10.01","sha256":"` + sha + `"}`
	cases := []struct {
		name        string
		opts        envOpts
		body        string
		wantStatus  int
		wantOutcome string
		wantPut     bool
	}{
		{"accepted", envOpts{rec: testRecord(testUUID, debianBlock)}, good, http.StatusNoContent, provision.OutcomeDone, true},
		{
			"repeated identical",
			envOpts{rec: testRecord(testUUID, debianBlock), state: &pxestate.Record{Image: "debian13", Version: "2026.10.01", SHA256: sha, Method: provision.MethodDisk}},
			good, http.StatusNoContent, provision.OutcomeDoneUnchanged, false,
		},
		{"wrong sha256", envOpts{rec: testRecord(testUUID, debianBlock)}, `{"image":"debian13","version":"2026.10.01","sha256":"` + strings.Repeat("0", 64) + `"}`, http.StatusConflict, provision.OutcomeDoneMismatch, false},
		{"wrong image", envOpts{rec: testRecord(testUUID, debianBlock)}, `{"image":"talos","version":"v1.14.2","sha256":""}`, http.StatusConflict, provision.OutcomeDoneMismatch, false},
		{"version differs from pin", envOpts{rec: testRecord(testUUID, "<!--#pxe\nimage: debian13\nversion: 2026.09.01\n-->")}, good, http.StatusConflict, provision.OutcomeDoneMismatch, false},
		{"state write fails", envOpts{rec: testRecord(testUUID, debianBlock), putErr: errors.New("403")}, good, http.StatusServiceUnavailable, provision.OutcomeStateError, false},
		{"manifest unavailable", envOpts{rec: testRecord(testUUID, debianBlock), manifestErr: errors.New("x")}, good, http.StatusServiceUnavailable, provision.OutcomeManifestError, false},
		{"malformed json", envOpts{rec: testRecord(testUUID, debianBlock)}, `{"image":`, http.StatusBadRequest, OutcomeBadRequest, false},
		{"unknown field", envOpts{rec: testRecord(testUUID, debianBlock)}, `{"image":"debian13","version":"2026.10.01","sha256":"` + sha + `","disk":"x"}`, http.StatusBadRequest, OutcomeBadRequest, false},
		{"too large", envOpts{rec: testRecord(testUUID, debianBlock)}, `{"image":"` + strings.Repeat("a", maxDoneBody) + `"}`, http.StatusBadRequest, OutcomeBadRequest, false},
		{"no block", envOpts{rec: testRecord(testUUID, "")}, good, http.StatusConflict, OutcomeNoBlock, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts)
			resp, _ := e.do(t, http.MethodPost, DonePath, tc.body)
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
			assertOneInfo(t, e, tc.wantOutcome)
			if tc.wantStatus == http.StatusServiceUnavailable {
				assert.Equal(t, retryAfter, resp.Header.Get("Retry-After"))
			}
			if tc.wantPut {
				assert.Equal(t, []pxestate.Record{{Image: "debian13", Version: "2026.10.01", SHA256: sha, ProvisionedAt: testNow, Method: provision.MethodDisk}}, e.state.puts)
			} else {
				assert.Empty(t, e.state.puts)
			}
		})
	}
}

func TestDiskProvisioningFlow(t *testing.T) {
	e := newEnv(t, envOpts{rec: testRecord(testUUID, debianBlock)})

	_, script := e.do(t, http.MethodGet, Path, "")
	assert.Equal(t, "#!ipxe\nchain /pxe/live.efi\n", script)

	resp, _ := e.do(t, http.MethodGet, LiveUKIPath, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	_, body := e.do(t, http.MethodGet, JobPath, "")
	var job provision.Job
	require.NoError(t, json.Unmarshal([]byte(body), &job))
	assert.Equal(t, imds.DefaultPXEDisk, job.Disk)

	report, err := json.Marshal(provision.DoneReport{Image: job.Image, Version: job.Version, SHA256: job.SHA256})
	require.NoError(t, err)
	resp, _ = e.do(t, http.MethodPost, DonePath, string(report))
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, script = e.do(t, http.MethodGet, Path, "")
	assert.Equal(t, provision.ExitScript, script, "boots from disk after done")
	resp, _ = e.do(t, http.MethodGet, LiveUKIPath, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp, _ = e.do(t, http.MethodGet, JobPath, "")
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}
