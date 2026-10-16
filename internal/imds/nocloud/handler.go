// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nocloud implements the cloud-init NoCloud datasource over HTTP
// ("nocloud-net"), as consumed by cloud-init and by Talos Linux's nocloud
// platform.
//
// URL structure served (with or without a trailing slash on the prefix):
//
//	GET /nocloud                → newline-separated file list
//	GET /nocloud/meta-data      → YAML: instance-id, local-hostname
//	GET /nocloud/user-data      → user-data (empty 200 if absent, 503 if it cannot be rendered)
//	GET /nocloud/vendor-data    → empty
//	GET /nocloud/network-config → network config YAML (always 200)
//
// Detection: set the VM's SMBIOS serial to
//
//	ds=nocloud-net;s=http://169.254.169.254/nocloud/
//
// optionally followed by ;h=<hostname>.
//
// Absent user-data is an empty 200 rather than a 404 because cloud-init's
// NoCloud datasource fails outright on a 404 for user-data, whereas both
// cloud-init and Talos treat an empty body as "no user-data". network-config
// is always served because Talos retries a 404 for minutes and only applies
// the meta-data hostname when it received a network-config.
package nocloud

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/imds/openstack"
)

// Prefix is the URL path prefix the NoCloud datasource is served under.
const Prefix = "/nocloud"

// fileListing is returned for GET /nocloud. Neither cloud-init nor Talos
// requires it, but it is useful for debugging.
const fileListing = "meta-data\nnetwork-config\nuser-data\nvendor-data\n"

// Server serves the NoCloud datasource. It implements [imds.Server].
type Server struct {
	userData imds.UserDataProvider
}

// NewServer returns a NoCloud server that obtains user data from userData.
func NewServer(userData imds.UserDataProvider) *Server {
	return &Server{userData: userData}
}

// NewHandler implements [imds.Server]. The returned handler expects to be
// mounted at both "/nocloud" and "/nocloud/".
func (s *Server) NewHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		rec, err := resolver.RecordByName(name, ifindex)
		if err != nil {
			http.Error(w, fmt.Sprintf("identity lookup failed: %v", err), http.StatusServiceUnavailable)
			return
		}

		rest, ok := strings.CutPrefix(req.URL.Path, Prefix)
		if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
			http.NotFound(w, req)
			return
		}

		switch strings.Trim(rest, "/") {
		case "":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, fileListing) //nolint:errcheck
		case "meta-data":
			serveYAML(w, metaDataFromRecord(rec))
		case "user-data":
			s.serveUserData(w, req, rec)
		case "vendor-data":
			w.Header().Set("Content-Type", "text/plain")
		case "network-config":
			data, err := networkConfigFromRecord(rec)
			if err != nil {
				http.Error(w, "failed to marshal response", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/yaml")
			w.Write(data) //nolint:errcheck
		default:
			http.NotFound(w, req)
		}
	})
}

func (s *Server) serveUserData(w http.ResponseWriter, req *http.Request, rec *identity.VMRecord) {
	userData, err := s.userData.UserData(req.Context(), rec)
	switch {
	case errors.Is(err, imds.ErrNoUserData):
		userData = ""
	case err != nil:
		imds.WriteUserDataUnavailable(w)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprint(w, userData) //nolint:errcheck
}

// MetaData is the YAML body served at /nocloud/meta-data.
type MetaData struct {
	// InstanceID is the SMBIOS UUID (falling back to the VMID), the same
	// value the OpenStack endpoint serves as "uuid".
	InstanceID string `yaml:"instance-id"`

	// LocalHostname is the VM name.
	LocalHostname string `yaml:"local-hostname,omitempty"`
}

func metaDataFromRecord(rec *identity.VMRecord) MetaData {
	md := openstack.MetadataFromRecord(rec)
	return MetaData{
		InstanceID:    md.UUID,
		LocalHostname: md.Hostname,
	}
}

// serveYAML marshals v to YAML and writes it to w. If marshaling fails, it
// writes a 500 response instead.
func serveYAML(w http.ResponseWriter, v any) {
	data, err := marshalYAML(v)
	if err != nil {
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(data) //nolint:errcheck
}

// marshalYAML encodes v as YAML with two-space indentation.
func marshalYAML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
