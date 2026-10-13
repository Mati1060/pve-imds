package imds

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const userDataOpenTag = "<!--#user-data"
const networkConfigOpenTag = "<!--#network-config"
const pxeOpenTag = "<!--#pxe"
const blockPrefix = "<!--#"
const userDataCloseTag = "-->"

// findBlockEnd finds the position of the closing --> for the current block.
// It uses LastIndex to allow --> sequences inside the content, but bounds the
// search to content before any subsequent <!--# block marker so that multiple
// blocks can coexist in any order.
func findBlockEnd(content string) int {
	bound := len(content)
	if idx := strings.Index(content, blockPrefix); idx > 0 {
		bound = idx
	}
	return strings.LastIndex(content[:bound], userDataCloseTag)
}

// userDataAttrRe matches the attribute list that may follow the opening
// "<!--#user-data" tag on the same line. Only a single secrets=<set> attribute
// is recognised; the value is captured verbatim (it may be empty or invalid)
// so that validation, not parsing, decides whether it is acceptable.
var userDataAttrRe = regexp.MustCompile(`^[ \t]+secrets=(\S*)[ \t]*\r?$`)

// blockContent returns the raw (untrimmed) content of the block that starts
// with openTag, or ("", false) when there is no such block or it is not
// closed.
func blockContent(description, openTag string) (string, bool) {
	_, after, ok := strings.Cut(description, openTag)
	if !ok {
		return "", false
	}

	end := findBlockEnd(after)
	if end < 0 {
		return "", false
	}

	return after[:end], true
}

// ParseNetworkConfig extracts embedded network configuration from a Proxmox VM
// description. The format follows the same HTML comment block convention as
// user-data, wrapping a standard cloud-init network-config document (v1 or v2):
//
//	<!--#network-config
//	network:
//	  version: 2
//	  ethernets:
//	    net0:
//	      addresses:
//	        - 192.168.1.10/24
//	      routes:
//	        - to: 0.0.0.0/0
//	          via: 192.168.1.1
//	-->
//
// Returns ("", false) when no opening tag is present, no closing "-->" follows
// the opening tag, or the trimmed content is empty.
func ParseNetworkConfig(description string) (string, bool) {
	raw, ok := blockContent(description, networkConfigOpenTag)
	if !ok {
		return "", false
	}

	content := strings.TrimSpace(raw)
	if content == "" {
		return "", false
	}

	return content, true
}

// pxeNameRe is the charset allowed for a <!--#pxe image and version. It
// keeps both safe to interpolate into iPXE scripts.
var pxeNameRe = regexp.MustCompile(`^[a-z0-9._-]+$`)

// pxeDiskRe is the form of a <!--#pxe disk: a stable /dev/disk/by-id path.
var pxeDiskRe = regexp.MustCompile(`^/dev/disk/by-id/[A-Za-z0-9._:-]+$`)

// DefaultPXEDisk is the disk a <!--#pxe block installs to when it names
// none: the first SCSI disk of a Proxmox VM.
const DefaultPXEDisk = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0"

var (
	// ErrNoPXEBlock is returned by [ParsePXEBlock] when the description has
	// no closed <!--#pxe block.
	ErrNoPXEBlock = errors.New("no pxe block")

	// ErrInvalidPXEBlock is returned by [ParsePXEBlock] when a <!--#pxe
	// block is present but its content is not valid.
	ErrInvalidPXEBlock = errors.New("invalid pxe block")
)

// PXEBlock is a parsed <!--#pxe block: the image a VM should be provisioned
// with.
type PXEBlock struct {
	// Image names the image to provision. It always matches
	// ^[a-z0-9._-]+$.
	Image string `yaml:"image"`

	// Version pins the image version. Empty means "latest", which only
	// applies at first provisioning. When set it matches ^[a-z0-9._-]+$.
	Version string `yaml:"version"`

	// Disk is the /dev/disk/by-id path a disk image is written to. It
	// defaults to [DefaultPXEDisk].
	Disk string `yaml:"disk"`
}

// ParsePXEBlock extracts the desired provisioning state from a Proxmox VM
// description. The block uses the same HTML comment convention as
// network-config and wraps a YAML mapping:
//
//	<!--#pxe
//	image: debian13        # required
//	version: 2026.10.01    # optional
//	disk: /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_drive-scsi0  # optional
//	-->
//
// Unknown keys are rejected. disk must match
// ^/dev/disk/by-id/[A-Za-z0-9._:-]+$ and defaults to [DefaultPXEDisk]. It returns an error wrapping [ErrNoPXEBlock]
// when there is no closed block, and one wrapping [ErrInvalidPXEBlock] that
// names the reason when the content is not valid YAML, image is missing or
// either value is outside ^[a-z0-9._-]+$.
func ParsePXEBlock(description string) (PXEBlock, error) {
	raw, ok := blockContent(description, pxeOpenTag)
	if !ok {
		return PXEBlock{}, ErrNoPXEBlock
	}

	var blk PXEBlock
	dec := yaml.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&blk); err != nil {
		if errors.Is(err, io.EOF) {
			return PXEBlock{}, fmt.Errorf("%w: image is required", ErrInvalidPXEBlock)
		}
		return PXEBlock{}, fmt.Errorf("%w: %w", ErrInvalidPXEBlock, err)
	}

	switch {
	case blk.Image == "":
		return PXEBlock{}, fmt.Errorf("%w: image is required", ErrInvalidPXEBlock)
	case !pxeNameRe.MatchString(blk.Image):
		return PXEBlock{}, fmt.Errorf("%w: image %q must match %s", ErrInvalidPXEBlock, blk.Image, pxeNameRe)
	case blk.Version != "" && !pxeNameRe.MatchString(blk.Version):
		return PXEBlock{}, fmt.Errorf("%w: version %q must match %s", ErrInvalidPXEBlock, blk.Version, pxeNameRe)
	case blk.Disk == "":
		blk.Disk = DefaultPXEDisk
	case !pxeDiskRe.MatchString(blk.Disk) || path.Base(blk.Disk) == "." || path.Base(blk.Disk) == "..":
		return PXEBlock{}, fmt.Errorf("%w: disk %q must match %s", ErrInvalidPXEBlock, blk.Disk, pxeDiskRe)
	}
	return blk, nil
}

// ParseUserData extracts embedded user-data from a Proxmox VM description.
//
// User-data is declared with an HTML comment block starting with the literal
// text "<!--#user-data" and ending at the last occurrence of "-->" before any
// subsequent <!--# block marker:
//
//	<!--#user-data
//	#cloud-config
//	users:
//	  - default
//	-->
//	other unparsed text
//
// The content between the opening tag and the closing "-->" is stripped of
// leading and trailing whitespace and returned. Using the last occurrence of
// "-->" (bounded by any subsequent block) rather than the first allows the
// user-data body to contain "-->" sequences without prematurely ending the
// block.
//
// Returns ("", false) when no opening tag is present, no closing "-->" follows
// the opening tag, or the trimmed content is empty.
func ParseUserData(description string) (string, bool) {
	raw, ok := blockContent(description, userDataOpenTag)
	if !ok {
		return "", false
	}

	userData := strings.TrimSpace(raw)
	if userData == "" {
		return "", false
	}

	return userData, true
}

// UserDataBlock is a parsed <!--#user-data block.
type UserDataBlock struct {
	// Content is the block body, stripped of leading and trailing whitespace.
	Content string

	// Templated is true when the opening line declared secrets=<set>. Only
	// templated blocks have {{ secret "..." }} placeholders rendered.
	Templated bool

	// SecretSet is the raw secrets=<set> value. It is not validated here.
	SecretSet string
}

// ParseUserDataBlock extracts embedded user-data like [ParseUserData], and
// additionally recognises an optional attribute on the opening line:
//
//	<!--#user-data secrets=worker
//	...config with {{ secret "token" }} placeholders...
//	-->
//
// The attribute must be on the same line as the opening tag and separated
// from it by whitespace. When the rest of the opening line is anything other
// than exactly one secrets=<set> attribute, the block is parsed exactly as
// [ParseUserData] parses it and Templated is false.
//
// Returns false when there is no block or its trimmed content is empty.
func ParseUserDataBlock(description string) (UserDataBlock, bool) {
	raw, ok := blockContent(description, userDataOpenTag)
	if !ok {
		return UserDataBlock{}, false
	}

	var blk UserDataBlock
	firstLine, rest, _ := strings.Cut(raw, "\n")
	if m := userDataAttrRe.FindStringSubmatch(firstLine); m != nil {
		blk.Templated = true
		blk.SecretSet = m[1]
		blk.Content = strings.TrimSpace(rest)
	} else {
		blk.Content = strings.TrimSpace(raw)
	}

	if blk.Content == "" {
		return UserDataBlock{}, false
	}
	return blk, true
}
