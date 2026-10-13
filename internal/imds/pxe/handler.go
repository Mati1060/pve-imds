// Package pxe serves GET /pxe, which a VM's iPXE ROM chains on every boot.
// The response is always an iPXE script that either provisions the VM or
// runs "exit" so the firmware falls through to the local disk.
//
// The desired state is the <!--#pxe block in the VM's Notes (see
// [imds.ParsePXEBlock]); the recorded state is a record in OpenBao keyed by
// the VM's SMBIOS UUID (see [pxestate]). pve-imds only reads Proxmox.
//
// Decision table:
//
//	identity lookup fails, or no valid SMBIOS UUID → exit
//	no valid <!--#pxe block                        → exit
//	state lookup fails                             → exit
//	no record                                      → provision
//	record image differs from block image          → provision
//	block version set and differs from record      → provision
//	otherwise                                      → exit
//
// An unpinned block (no version) never reprovisions because a newer image
// exists: "latest" only applies at first provisioning.
//
// Every response is a 200, even on internal errors, because iPXE treats any
// other status as a failure and retries instead of booting.
package pxe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/wyattanderson/pve-imds/internal/imds"
	"github.com/wyattanderson/pve-imds/internal/pxestate"
)

// Path is the URL path the endpoint is served at.
const Path = "/pxe"

// Outcomes logged for each request.
const (
	OutcomeNoIdentity       = "no_identity"
	OutcomeNoUUID           = "no_uuid"
	OutcomeNoBlock          = "no_block"
	OutcomeStateError       = "state_error"
	OutcomeProvisionNew     = "provision_new"
	OutcomeProvisionChanged = "provision_changed"
	OutcomeProvisioned      = "provisioned"
)

// exitScript makes iPXE return to the firmware, which boots the next device.
const exitScript = "#!ipxe\nexit\n"

// StateStore reads provisioning records. *pxestate.Store implements it.
type StateStore interface {
	Get(ctx context.Context, uuid string) (rec pxestate.Record, found bool, err error)
}

// ProvisionRequest is what a provision script is built for.
type ProvisionRequest struct {
	VMID int
	// UUID is the normalized SMBIOS UUID.
	UUID string
	// Image and Version come from the <!--#pxe block; Version is empty
	// when unpinned.
	Image   string
	Version string
}

// ScriptFunc builds the iPXE script that provisions a VM. The returned
// script must start with "#!ipxe\n".
type ScriptFunc func(ProvisionRequest) string

// Server serves the /pxe endpoint.
type Server struct {
	log       *slog.Logger
	state     StateStore
	provision ScriptFunc
}

// NewServer returns a Server that reads provisioning records from state and
// answers "provision" with [PlaceholderScript].
func NewServer(log *slog.Logger, state StateStore) *Server {
	return &Server{log: log, state: state, provision: PlaceholderScript}
}

// WithScript returns a copy of s that builds provision scripts with fn.
func (s *Server) WithScript(fn ScriptFunc) *Server {
	c := *s
	c.provision = fn
	return &c
}

// ipxeSafeRe matches values that can be interpolated into an iPXE script
// verbatim: no whitespace, quotes or ${...} expansions.
var ipxeSafeRe = regexp.MustCompile(`^[a-z0-9._-]+$`)

// PlaceholderScript only reports what would be provisioned, then boots from
// disk. It falls back to the exit script if a value is not safe to
// interpolate, which [imds.ParsePXEBlock] already guarantees.
func PlaceholderScript(req ProvisionRequest) string {
	version := req.Version
	if version == "" {
		version = "latest"
	}
	if !ipxeSafeRe.MatchString(req.Image) || !ipxeSafeRe.MatchString(version) {
		return exitScript
	}
	return "#!ipxe\n" +
		"echo pve-imds: would provision " + req.Image + " " + version + " for vm " + strconv.Itoa(req.VMID) + "\n" +
		"sleep 10\n" +
		"exit\n"
}

// decision is the result of [Server.decide].
type decision struct {
	outcome string
	script  string
	vmid    any // int once identity is known
	uuid    string
	image   string
	version string
}

// NewHandler returns the handler for GET /pxe on the named tap interface.
func (s *Server) NewHandler(resolver imds.Resolver, name string, ifindex int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		d := s.decide(req.Context(), resolver, name, ifindex)
		s.log.InfoContext(req.Context(), "pxe: decision",
			"vmid", d.vmid,
			"uuid", d.uuid,
			"image", d.image,
			"version", d.version,
			"outcome", d.outcome,
		)

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, d.script) //nolint:errcheck
	})
}

func (s *Server) decide(ctx context.Context, resolver imds.Resolver, name string, ifindex int32) decision {
	d := decision{script: exitScript, vmid: ""}

	rec, err := resolver.RecordByName(name, ifindex)
	if err != nil || rec == nil || rec.Config == nil {
		s.log.WarnContext(ctx, "pxe: identity lookup failed", "iface", name, "err", err)
		d.outcome = OutcomeNoIdentity
		return d
	}
	d.vmid = rec.VMID
	log := s.log.With("vmid", rec.VMID)

	uuid, err := pxestate.NormalizeUUID(rec.Config.SMBIOS["uuid"])
	if err != nil {
		log.WarnContext(ctx, "pxe: no usable SMBIOS uuid", "err", err)
		d.outcome = OutcomeNoUUID
		return d
	}
	d.uuid = uuid

	blk, err := imds.ParsePXEBlock(rec.Config.Description)
	if err != nil {
		if !errors.Is(err, imds.ErrNoPXEBlock) {
			log.WarnContext(ctx, "pxe: ignoring invalid pxe block", "reason", err)
		}
		d.outcome = OutcomeNoBlock
		return d
	}
	d.image, d.version = blk.Image, blk.Version

	state, found, err := s.state.Get(ctx, uuid)
	switch {
	case err != nil:
		log.WarnContext(ctx, "pxe: state lookup failed", "uuid", uuid, "err", err)
		d.outcome = OutcomeStateError
		return d
	case !found:
		d.outcome = OutcomeProvisionNew
	case state.Image != blk.Image:
		d.outcome = OutcomeProvisionChanged
	case blk.Version != "" && blk.Version != state.Version:
		d.outcome = OutcomeProvisionChanged
	default:
		d.outcome = OutcomeProvisioned
		return d
	}

	d.script = s.provision(ProvisionRequest{
		VMID:    rec.VMID,
		UUID:    uuid,
		Image:   blk.Image,
		Version: blk.Version,
	})
	return d
}

// Ensure *pxestate.Store satisfies StateStore.
var _ StateStore = (*pxestate.Store)(nil)
