package provision

import "github.com/wyattanderson/pve-imds/pkg/manifest"

// The manifest types are defined in package manifest so that other
// programs can validate manifests with the same code.
type (
	// Manifest is [manifest.Manifest].
	Manifest = manifest.Manifest
	// Image is [manifest.Image].
	Image = manifest.Image
	// Version is [manifest.Version].
	Version = manifest.Version
	// ImageType is [manifest.ImageType].
	ImageType = manifest.ImageType
	// BootMode is [manifest.BootMode].
	BootMode = manifest.BootMode
)

// Image types and boot modes; see package manifest.
const (
	TypeDisk   = manifest.TypeDisk
	TypeChain  = manifest.TypeChain
	BootOnce   = manifest.BootOnce
	BootAlways = manifest.BootAlways
)
