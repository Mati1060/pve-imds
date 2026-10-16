// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pxe serves the PXE provisioning endpoints for one tap interface.
// It only maps the VM behind the interface to the inputs of
// [provision.Provisioner]; the decisions are made there.
//
//	GET  /pxe          iPXE script: provision, or exit to boot from disk
//	GET  /pxe/live.efi the live OS UKI, while a disk image is to be written
//	GET  /pxe/job      the disk image the live OS should write (JSON)
//	POST /pxe/done     the live OS reports the image it wrote
//
// The desired state is the <!--#pxe block in the VM's Notes (see
// [imds.ParsePXEBlock]); the recorded state is keyed by the VM's SMBIOS
// UUID. pve-imds only reads Proxmox.
//
// /pxe always answers 200 with an iPXE script, even on internal errors,
// because iPXE treats any other status as a failure and retries instead of
// booting. Every failure there serves "exit".
package pxe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/provision"
	"github.com/wyattanderson/pve-imds/internal/pxestate"
)

// Paths of the endpoints.
const (
	Path        = "/pxe"
	LiveUKIPath = "/pxe/live.efi"
	JobPath     = "/pxe/job"
	DonePath    = "/pxe/done"
)

// Outcomes logged before the provisioner is consulted.
const (
	OutcomeNoIdentity = "no_identity"
	OutcomeNoUUID     = "no_uuid"
	OutcomeNoBlock    = "no_block"
	OutcomeBadRequest = "bad_request"
)

// retryAfter is sent with 503 responses to /pxe/done.
const retryAfter = "5"

// maxDoneBody bounds the size of a /pxe/done request body.
const maxDoneBody = 4 << 10

// Server serves the PXE endpoints.
type Server struct {
	log     *slog.Logger
	prov    *provision.Provisioner
	liveUKI string
}

// NewServer returns a Server that decides with prov and serves the live
// UKI from liveUKI.
func NewServer(log *slog.Logger, prov *provision.Provisioner, liveUKI string) *Server {
	return &Server{log: log, prov: prov, liveUKI: liveUKI}
}

// Register adds the PXE endpoints for the named tap interface to mux.
func (s *Server) Register(mux *http.ServeMux, resolver imds.Resolver, name string, ifindex int32) {
	mux.Handle("GET "+Path, s.bootHandler(resolver, name, ifindex))
	mux.Handle("GET "+LiveUKIPath, s.liveUKIHandler(resolver, name, ifindex))
	mux.Handle("GET "+JobPath, s.jobHandler(resolver, name, ifindex))
	mux.Handle("POST "+DonePath, s.doneHandler(resolver, name, ifindex))
}

// vm is the VM behind a request, as far as it could be identified.
type vm struct {
	vmid    any // int once identity is known
	uuid    string
	desired provision.Desired
	// outcome is set when the VM has no usable identity or <!--#pxe block.
	outcome string
}

// identify maps the VM behind the interface to provisioning inputs. Failures
// are logged as warnings, except a missing <!--#pxe block.
func (s *Server) identify(req *http.Request, resolver imds.Resolver, name string, ifindex int32) vm {
	ctx := req.Context()
	v := vm{vmid: ""}

	rec, err := resolver.RecordByName(name, ifindex)
	if err != nil || rec == nil || rec.Config == nil {
		s.log.WarnContext(ctx, "pxe: identity lookup failed", "iface", name, "path", req.URL.Path, "err", err)
		v.outcome = OutcomeNoIdentity
		return v
	}
	v.vmid = rec.VMID

	uuid, err := pxestate.NormalizeUUID(rec.Config.SMBIOS["uuid"])
	if err != nil {
		s.log.WarnContext(ctx, "pxe: no usable SMBIOS uuid", "vmid", rec.VMID, "err", err)
		v.outcome = OutcomeNoUUID
		return v
	}
	v.uuid = uuid

	blk, err := imds.ParsePXEBlock(rec.Config.Description)
	if err != nil {
		if !errors.Is(err, imds.ErrNoPXEBlock) {
			s.log.WarnContext(ctx, "pxe: ignoring invalid pxe block", "vmid", rec.VMID, "reason", err)
		}
		v.outcome = OutcomeNoBlock
		return v
	}
	v.desired = provision.Desired{Image: blk.Image, Version: blk.Version, Disk: blk.Disk}
	return v
}

// logRequest writes the one info line every request gets. version is the
// resolved version when known, else the desired one.
func (s *Server) logRequest(req *http.Request, v vm, version, outcome string, extra ...any) {
	if version == "" {
		version = v.desired.Version
	}
	args := append([]any{
		"vmid", v.vmid,
		"uuid", v.uuid,
		"image", v.desired.Image,
		"version", version,
		"outcome", outcome,
	}, extra...)
	s.log.InfoContext(req.Context(), "pxe: "+req.URL.Path, args...)
}

// warnPlan logs why a plan failed, if it did.
func (s *Server) warnPlan(req *http.Request, v vm, plan provision.Plan) {
	if plan.Err != nil {
		s.log.WarnContext(req.Context(), "pxe: "+plan.Outcome, "vmid", v.vmid, "uuid", v.uuid, "image", v.desired.Image, "err", plan.Err)
	}
}

func (s *Server) bootHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		script := provision.ExitScript
		v := s.identify(req, resolver, name, ifindex)
		outcome, version := v.outcome, ""
		if outcome == "" {
			var plan provision.Plan
			plan, script = s.prov.Boot(req.Context(), v.uuid, v.desired)
			s.warnPlan(req, v, plan)
			outcome, version = plan.Outcome, plan.Version
		}
		s.logRequest(req, v, version, outcome)

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, script) //nolint:errcheck
	})
}

func (s *Server) liveUKIHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		var written int64
		v := s.identify(req, resolver, name, ifindex)
		outcome, version := v.outcome, ""
		defer func() {
			s.logRequest(req, v, version, outcome, "bytes", written, "duration", time.Since(start))
		}()
		if outcome != "" {
			http.NotFound(w, req)
			return
		}

		plan := s.prov.Plan(req.Context(), v.uuid, v.desired)
		s.warnPlan(req, v, plan)
		outcome, version = plan.Outcome, plan.Version
		if !plan.IsDiskProvision() {
			http.NotFound(w, req)
			return
		}

		// Opened per request so that the file can be replaced without a
		// restart.
		f, err := os.Open(s.liveUKI)
		var fi os.FileInfo
		if err == nil {
			defer f.Close() //nolint:errcheck
			fi, err = f.Stat()
		}
		if err == nil && !fi.Mode().IsRegular() {
			err = fmt.Errorf("%s is not a regular file", s.liveUKI)
		}
		if err != nil {
			s.log.WarnContext(req.Context(), "pxe: live UKI unavailable", "vmid", v.vmid, "err", err)
			outcome = provision.OutcomeLiveUKIMissing
			http.NotFound(w, req)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		written, _ = io.CopyN(w, f, fi.Size())
	})
}

// jsonError is the body of a JSON error response.
type jsonError struct {
	Error string `json:"error"`
	// Outcome is the decision that led to the error.
	Outcome string `json:"outcome"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func (s *Server) jobHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		v := s.identify(req, resolver, name, ifindex)
		if v.outcome != "" {
			s.logRequest(req, v, "", v.outcome)
			writeJSON(w, http.StatusConflict, jsonError{Error: "no provisioning job", Outcome: v.outcome})
			return
		}

		job, plan, ok := s.prov.Job(req.Context(), v.uuid, v.desired)
		s.warnPlan(req, v, plan)
		s.logRequest(req, v, plan.Version, plan.Outcome)
		if !ok {
			writeJSON(w, http.StatusConflict, jsonError{Error: "no provisioning job", Outcome: plan.Outcome})
			return
		}
		writeJSON(w, http.StatusOK, job)
	})
}

func (s *Server) doneHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		v := s.identify(req, resolver, name, ifindex)
		if v.outcome != "" {
			s.logRequest(req, v, "", v.outcome)
			writeJSON(w, http.StatusConflict, jsonError{Error: "not provisioning", Outcome: v.outcome})
			return
		}

		var report provision.DoneReport
		dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, maxDoneBody))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&report); err != nil {
			s.logRequest(req, v, "", OutcomeBadRequest)
			writeJSON(w, http.StatusBadRequest, jsonError{Error: "invalid request body", Outcome: OutcomeBadRequest})
			return
		}

		outcome, err := s.prov.Done(req.Context(), v.uuid, v.desired, report)
		if err != nil {
			s.log.WarnContext(req.Context(), "pxe: done rejected", "vmid", v.vmid, "uuid", v.uuid, "outcome", outcome, "err", err)
		}
		s.logRequest(req, v, report.Version, outcome)
		switch {
		case errors.Is(err, provision.ErrUnavailable):
			w.Header().Set("Retry-After", retryAfter)
			writeJSON(w, http.StatusServiceUnavailable, jsonError{Error: "temporarily unavailable", Outcome: outcome})
		case err != nil:
			writeJSON(w, http.StatusConflict, jsonError{Error: err.Error(), Outcome: outcome})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
}
