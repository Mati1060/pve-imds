// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package ec2

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/userdata"
	"github.com/wyattanderson/pve-imds/internal/vmconfig"
)

type fakeResolver struct {
	rec *identity.VMRecord
}

func (f *fakeResolver) RecordByName(_ string, _ int32) (*identity.VMRecord, error) {
	return f.rec, nil
}

func getUserData(t *testing.T, desc string) (*http.Response, string) {
	t.Helper()
	rec := &identity.VMRecord{VMID: 100, Config: &vmconfig.VMConfig{Description: desc}}
	handler := NewServer(userdata.New(slog.New(slog.DiscardHandler), nil, nil)).NewHandler(&fakeResolver{rec: rec}, "tap100i0", 3)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/latest/user-data", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, string(body)
}

func TestUserDataPresent(t *testing.T) {
	resp, body := getUserData(t, "<!--#user-data\n#cloud-config\n-->")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "#cloud-config", body)
}

func TestUserDataAbsent(t *testing.T) {
	resp, _ := getUserData(t, "plain")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestUserDataTemplatedWithoutSecretsIs503(t *testing.T) {
	resp, body := getUserData(t, "<!--#user-data secrets=worker\ntoken: {{ secret \"t\" }}\n-->")
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
	assert.NotContains(t, body, "secret")
}
