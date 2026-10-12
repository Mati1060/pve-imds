// Package pvepool resolves which Proxmox resource pool a VM belongs to.
//
// Pool membership is not stored in the VM config but in /etc/pve/user.cfg,
// one line per pool:
//
//	pool:<poolid>:<comment>:<vmid>,<vmid>,...:<storage>,...:
//
// /etc/pve is the cluster filesystem (pmxcfs). A pool edited on another node
// is replicated into this node's copy without generating an inotify event, so
// the file is re-read on every lookup rather than watched. It is small and
// pmxcfs serves it from memory, and lookups only happen for templated
// user-data, so this is cheap and always current.
package pvepool

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// DefaultUserCfgPath is the location of the Proxmox user/ACL/pool config.
const DefaultUserCfgPath = "/etc/pve/user.cfg"

// poolIDRe mirrors PVE::AccessControl::verify_poolname: up to three
// '/'-separated levels of [A-Za-z0-9._-].
var poolIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,2}$`)

// listSepRe mirrors PVE::Tools::split_list.
var listSepRe = regexp.MustCompile(`[;,\x00\s]+`)

// Lookup reads pool membership from user.cfg.
type Lookup struct {
	fs   afero.Fs
	path string
}

// New returns a Lookup that reads path from fs.
func New(fs afero.Fs, path string) *Lookup {
	return &Lookup{fs: fs, path: path}
}

// PoolOf returns the pool that vmid belongs to. ok is false when the VM is
// not in any pool. Like Proxmox, a VMID listed in several pools belongs to
// the first one; pools with invalid IDs are ignored.
func (l *Lookup) PoolOf(vmid int) (pool string, ok bool, err error) {
	raw, err := afero.ReadFile(l.fs, l.path)
	if err != nil {
		return "", false, fmt.Errorf("pvepool: read %s: %w", l.path, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, found := strings.CutPrefix(line, "pool:")
		if !found {
			continue
		}

		// <poolid>:<comment>:<vmlist>:<storelist>:
		fields := strings.Split(rest, ":")
		if len(fields) < 3 || !poolIDRe.MatchString(fields[0]) {
			continue
		}
		for _, v := range listSepRe.Split(fields[2], -1) {
			if id, err := strconv.Atoi(v); err == nil && id == vmid {
				return fields[0], true, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", false, fmt.Errorf("pvepool: scan %s: %w", l.path, err)
	}
	return "", false, nil
}
