package nocloud

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/wyattanderson/pve-imds/internal/identity"
	"github.com/wyattanderson/pve-imds/internal/imds"
)

// networkConfigV2 is the cloud-init network config v2 document generated
// when the VM's Notes have no usable <!--#network-config block.
type networkConfigV2 struct {
	Version   int                   `yaml:"version"`
	Ethernets map[string]ethernetV2 `yaml:"ethernets"`
}

type ethernetV2 struct {
	Match matchV2 `yaml:"match"`
	DHCP4 bool    `yaml:"dhcp4"`
	MTU   int     `yaml:"mtu,omitempty"`
}

type matchV2 struct {
	MACAddress quotedString `yaml:"macaddress"`
}

// quotedString is always emitted double-quoted. MAC addresses made only of
// digits (e.g. 52:54:00:12:34:56) are sexagesimal integers to YAML 1.1
// parsers such as PyYAML, so they must never be emitted bare.
type quotedString string

// MarshalYAML implements yaml.Marshaler.
func (q quotedString) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: string(q)}, nil
}

// networkConfigFromRecord returns the network-config document for rec.
//
// If the VM's Notes contain a <!--#network-config block holding a v1 or v2
// network config (bare, or wrapped in a top-level "network:" key, both of
// which cloud-init and Talos accept), it is served verbatim. Otherwise one
// DHCPv4 entry per NIC is generated, matched by MAC — the same default the
// OpenStack network_data.json uses.
func networkConfigFromRecord(rec *identity.VMRecord) ([]byte, error) {
	if raw, ok := imds.ParseNetworkConfig(rec.Config.Description); ok {
		err := validateNetworkConfig(raw)
		if err == nil {
			return []byte(raw + "\n"), nil
		}
		slog.Warn("invalid network-config in VM notes, falling back to DHCP",
			"vmid", rec.VMID, "error", err)
	}
	return defaultNetworkConfig(rec)
}

// validateNetworkConfig checks that raw is YAML with a version of 1 or 2,
// either at the top level or under a "network" key.
func validateNetworkConfig(raw string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return err
	}
	if inner, ok := doc["network"].(map[string]any); ok {
		doc = inner
	}
	if v, ok := doc["version"].(int); ok && (v == 1 || v == 2) {
		return nil
	}
	return fmt.Errorf("network-config version must be 1 or 2, got %v", doc["version"])
}

func defaultNetworkConfig(rec *identity.VMRecord) ([]byte, error) {
	indices := make([]int, 0, len(rec.Config.Networks))
	for idx := range rec.Config.Networks {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	cfg := networkConfigV2{
		Version:   2,
		Ethernets: make(map[string]ethernetV2, len(indices)),
	}
	for _, idx := range indices {
		nic := rec.Config.Networks[idx]
		eth := ethernetV2{
			Match: matchV2{MACAddress: quotedString(strings.ToLower(nic.MAC.String()))},
			DHCP4: true,
		}
		// Proxmox uses mtu=1 to mean "inherit the bridge MTU"; only pass
		// through explicit values.
		if nic.MTU > 1 {
			eth.MTU = nic.MTU
		}
		cfg.Ethernets[fmt.Sprintf("net%d", idx)] = eth
	}

	return marshalYAML(cfg)
}
