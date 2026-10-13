package pxe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/pxestate"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

const testUUID = "2c8c7c76-a26c-4eb7-b04c-bf52bc095b81"

type fakeResolver struct {
	rec *identity.VMRecord
	err error
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, f.err
}

// fakeState returns a fixed record, or an error. It records the UUIDs it
// was asked for.
type fakeState struct {
	rec   *pxestate.Record
	err   error
	calls []string
}

func (f *fakeState) Get(_ context.Context, uuid string) (pxestate.Record, bool, error) {
	f.calls = append(f.calls, uuid)
	if f.err != nil {
		return pxestate.Record{}, false, f.err
	}
	if f.rec == nil {
		return pxestate.Record{}, false, nil
	}
	return *f.rec, true, nil
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

const provisionDebian13Latest = "#!ipxe\necho pve-imds: would provision debian13 latest for vm 500\nsleep 10\nexit\n"

const provisionDebian13Pinned = "#!ipxe\necho pve-imds: would provision debian13 2026.10.01 for vm 500\nsleep 10\nexit\n"

func TestHandlerDecisionTable(t *testing.T) {
	unpinned := "<!--#pxe\nimage: debian13\n-->"
	pinned := "<!--#pxe\nimage: debian13\nversion: 2026.10.01\n-->"

	cases := []struct {
		name         string
		rec          *identity.VMRecord
		resolverErr  error
		state        *pxestate.Record
		stateErr     error
		wantBody     string
		wantOutcome  string
		wantWarn     bool
		wantStateGet bool
	}{
		{
			name:        "identity lookup fails",
			resolverErr: errors.New("no such interface"),
			wantBody:    exitScript,
			wantOutcome: OutcomeNoIdentity,
			wantWarn:    true,
		},
		{
			name:        "no smbios uuid",
			rec:         testRecord("", unpinned),
			wantBody:    exitScript,
			wantOutcome: OutcomeNoUUID,
			wantWarn:    true,
		},
		{
			name:        "invalid smbios uuid",
			rec:         testRecord("not-a-uuid", unpinned),
			wantBody:    exitScript,
			wantOutcome: OutcomeNoUUID,
			wantWarn:    true,
		},
		{
			name:        "no pxe block",
			rec:         testRecord(testUUID, "just notes"),
			wantBody:    exitScript,
			wantOutcome: OutcomeNoBlock,
		},
		{
			name:        "invalid pxe block",
			rec:         testRecord(testUUID, "<!--#pxe\nimage: Debian13\n-->"),
			wantBody:    exitScript,
			wantOutcome: OutcomeNoBlock,
			wantWarn:    true,
		},
		{
			name:         "state lookup fails",
			rec:          testRecord(testUUID, unpinned),
			stateErr:     errors.New("secrets: server returned 403 Forbidden"),
			wantBody:     exitScript,
			wantOutcome:  OutcomeStateError,
			wantWarn:     true,
			wantStateGet: true,
		},
		{
			name:         "no record, unpinned",
			rec:          testRecord(testUUID, unpinned),
			wantBody:     provisionDebian13Latest,
			wantOutcome:  OutcomeProvisionNew,
			wantStateGet: true,
		},
		{
			name:         "no record, pinned",
			rec:          testRecord(testUUID, pinned),
			wantBody:     provisionDebian13Pinned,
			wantOutcome:  OutcomeProvisionNew,
			wantStateGet: true,
		},
		{
			name:         "image changed",
			rec:          testRecord(testUUID, unpinned),
			state:        &pxestate.Record{Image: "debian12", Version: "2025.06.01"},
			wantBody:     provisionDebian13Latest,
			wantOutcome:  OutcomeProvisionChanged,
			wantStateGet: true,
		},
		{
			name:         "pinned version changed",
			rec:          testRecord(testUUID, pinned),
			state:        &pxestate.Record{Image: "debian13", Version: "test"},
			wantBody:     provisionDebian13Pinned,
			wantOutcome:  OutcomeProvisionChanged,
			wantStateGet: true,
		},
		{
			name:         "pinned version matches",
			rec:          testRecord(testUUID, pinned),
			state:        &pxestate.Record{Image: "debian13", Version: "2026.10.01"},
			wantBody:     exitScript,
			wantOutcome:  OutcomeProvisioned,
			wantStateGet: true,
		},
		{
			name:         "unpinned never reprovisions for a newer image",
			rec:          testRecord(testUUID, unpinned),
			state:        &pxestate.Record{Image: "debian13", Version: "2020.01.01"},
			wantBody:     exitScript,
			wantOutcome:  OutcomeProvisioned,
			wantStateGet: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			state := &fakeState{rec: tc.state, err: tc.stateErr}
			h := NewServer(log, state).NewHandler(&fakeResolver{rec: tc.rec, err: tc.resolverErr}, "tap500i0", 7)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, Path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			resp := w.Result()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))
			assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
			assert.True(t, strings.HasPrefix(string(body), "#!ipxe\n"))
			assert.Equal(t, tc.wantBody, string(body))

			if tc.wantStateGet {
				assert.Equal(t, []string{testUUID}, state.calls)
			} else {
				assert.Empty(t, state.calls)
			}

			lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
			var infos []string
			var warned bool
			for _, l := range lines {
				switch {
				case strings.Contains(l, `"level":"INFO"`):
					infos = append(infos, l)
				case strings.Contains(l, `"level":"WARN"`):
					warned = true
				}
			}
			require.Len(t, infos, 1, "exactly one info line per request")
			assert.Contains(t, infos[0], `"outcome":"`+tc.wantOutcome+`"`)
			for _, key := range []string{"vmid", "uuid", "image", "version"} {
				assert.Contains(t, infos[0], `"`+key+`":`)
			}
			assert.Equal(t, tc.wantWarn, warned)
		})
	}
}

func TestHandlerLogFields(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	rec := testRecord(strings.ToUpper(testUUID), "<!--#pxe\nimage: debian13\nversion: 2026.10.01\n-->")
	h := NewServer(log, &fakeState{}).NewHandler(&fakeResolver{rec: rec}, "tap500i0", 7)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(context.Background(), http.MethodGet, Path, nil))

	out := logs.String()
	assert.Contains(t, out, `"vmid":500`)
	assert.Contains(t, out, `"uuid":"`+testUUID+`"`, "uuid is logged lowercased")
	assert.Contains(t, out, `"image":"debian13"`)
	assert.Contains(t, out, `"version":"2026.10.01"`)
	assert.Contains(t, out, `"outcome":"provision_new"`)
}

func TestWithScript(t *testing.T) {
	var got ProvisionRequest
	s := NewServer(slog.New(slog.DiscardHandler), &fakeState{}).WithScript(func(r ProvisionRequest) string {
		got = r
		return "#!ipxe\nchain http://example/live\n"
	})
	rec := testRecord(testUUID, "<!--#pxe\nimage: debian13\n-->")
	w := httptest.NewRecorder()
	s.NewHandler(&fakeResolver{rec: rec}, "tap500i0", 7).ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, Path, nil))

	assert.Equal(t, "#!ipxe\nchain http://example/live\n", w.Body.String())
	assert.Equal(t, ProvisionRequest{VMID: 500, UUID: testUUID, Image: "debian13"}, got)
}

func TestPlaceholderScriptRejectsUnsafeValues(t *testing.T) {
	assert.Equal(t, exitScript, PlaceholderScript(ProvisionRequest{VMID: 1, Image: "${x}"}))
	assert.Equal(t, exitScript, PlaceholderScript(ProvisionRequest{VMID: 1, Image: "a", Version: "1 2"}))
	assert.Equal(t, provisionDebian13Latest, PlaceholderScript(ProvisionRequest{VMID: 500, Image: "debian13"}))
}
