package imds

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUserData_Basic(t *testing.T) {
	desc := "<!--#user-data\n#cloud-config\nusers:\n  - default\n-->\nother text"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config\nusers:\n  - default", got)
}

func TestParseUserData_NoMarker(t *testing.T) {
	_, ok := ParseUserData("just a plain description")
	assert.False(t, ok)
}

func TestParseUserData_NoClosingTag(t *testing.T) {
	_, ok := ParseUserData("<!--#user-data\n#cloud-config\n")
	assert.False(t, ok)
}

func TestParseUserData_EmptyContent(t *testing.T) {
	// Whitespace-only content between the tags is treated as absent.
	_, ok := ParseUserData("<!--#user-data\n   \n-->")
	assert.False(t, ok)
}

func TestParseUserData_WhitespaceStripped(t *testing.T) {
	desc := "<!--#user-data\n\n  #cloud-config\n\n-->"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", got)
}

func TestParseUserData_ContentContainsClosingTag(t *testing.T) {
	// The user-data body itself contains "-->". The parser must use the LAST
	// occurrence of "-->" as the end of the block, not the first.
	desc := "<!--#user-data\n# yaml comment --> still user-data\nruncmd: []\n-->\nignored"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "# yaml comment --> still user-data\nruncmd: []", got)
}

func TestParseUserData_TextBeforeMarker(t *testing.T) {
	// Text before the opening tag is ignored.
	desc := "human-readable summary\n\n<!--#user-data\n#cloud-config\n-->"
	got, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", got)
}

func TestParseUserData_EmptyDescription(t *testing.T) {
	_, ok := ParseUserData("")
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// ParseNetworkConfig
// ---------------------------------------------------------------------------

func TestParseNetworkConfig_Basic(t *testing.T) {
	desc := "<!--#network-config\nnet0:\n  type: ipv4\n  ip_address: 10.0.0.5\n-->\nother text"
	got, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  type: ipv4\n  ip_address: 10.0.0.5", got)
}

func TestParseNetworkConfig_NoMarker(t *testing.T) {
	_, ok := ParseNetworkConfig("just a plain description")
	assert.False(t, ok)
}

func TestParseNetworkConfig_NoClosingTag(t *testing.T) {
	_, ok := ParseNetworkConfig("<!--#network-config\nnet0:\n  type: ipv4\n")
	assert.False(t, ok)
}

func TestParseNetworkConfig_EmptyContent(t *testing.T) {
	_, ok := ParseNetworkConfig("<!--#network-config\n   \n-->")
	assert.False(t, ok)
}

func TestParseNetworkConfig_WhitespaceStripped(t *testing.T) {
	desc := "<!--#network-config\n\n  net0:\n    type: ipv4\n\n-->"
	got, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n    type: ipv4", got)
}

func TestParseNetworkConfig_ContentContainsClosingTag(t *testing.T) {
	desc := "<!--#network-config\nnet0:\n  # comment --> still config\n  type: ipv4\n-->\nignored"
	got, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  # comment --> still config\n  type: ipv4", got)
}

func TestParseNetworkConfig_TextBeforeMarker(t *testing.T) {
	desc := "human-readable summary\n\n<!--#network-config\nnet0:\n  type: dhcp\n-->"
	got, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  type: dhcp", got)
}

func TestParseNetworkConfig_EmptyDescription(t *testing.T) {
	_, ok := ParseNetworkConfig("")
	assert.False(t, ok)
}

func TestParseNetworkConfig_CoexistsWithUserData_NetworkFirst(t *testing.T) {
	desc := "<!--#network-config\nnet0:\n  type: ipv4\n-->\n<!--#user-data\n#cloud-config\n-->"
	ud, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", ud)
	nc, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  type: ipv4", nc)
}

func TestParseNetworkConfig_CoexistsWithUserData_UserDataFirst(t *testing.T) {
	desc := "<!--#user-data\n#cloud-config\n-->\n<!--#network-config\nnet0:\n  type: ipv6_slaac\n-->"
	ud, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "#cloud-config", ud)
	nc, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  type: ipv6_slaac", nc)
}

func TestParseUserData_ContainsClosingTag_CoexistsWithNetworkConfig(t *testing.T) {
	desc := "<!--#user-data\n# comment --> still user-data\nruncmd: []\n-->\n<!--#network-config\nnet0:\n  type: ipv4\n-->"
	ud, ok := ParseUserData(desc)
	require.True(t, ok)
	assert.Equal(t, "# comment --> still user-data\nruncmd: []", ud)
	nc, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "net0:\n  type: ipv4", nc)
}

// ---------------------------------------------------------------------------
// ParseUserDataBlock
// ---------------------------------------------------------------------------

func TestParseUserDataBlock_Legacy(t *testing.T) {
	// Without secrets= the block parses exactly as ParseUserData does.
	descs := []string{
		"<!--#user-data\n#cloud-config\nusers:\n  - default\n-->\nother text",
		"<!--#user-data\n# yaml comment --> still user-data\nruncmd: []\n-->\nignored",
		"human-readable summary\n\n<!--#user-data\n#cloud-config\n-->",
		"<!--#user-data #cloud-config\nruncmd: []\n-->",
		"<!--#user-data\nsecrets=worker\nmachine: {}\n-->",
		"<!--#user-datasecrets=worker\nmachine: {}\n-->",
		"<!--#user-data secrets=worker other=1\nmachine: {}\n-->",
	}
	for _, desc := range descs {
		want, ok := ParseUserData(desc)
		require.True(t, ok, desc)
		blk, ok := ParseUserDataBlock(desc)
		require.True(t, ok, desc)
		assert.False(t, blk.Templated, desc)
		assert.Empty(t, blk.SecretSet, desc)
		assert.Equal(t, want, blk.Content, desc)
	}
}

func TestParseUserDataBlock_Secrets(t *testing.T) {
	desc := "<!--#user-data secrets=worker\nversion: v1alpha1\ntoken: {{ secret \"token\" }}\n---\nkind: Foo\n-->\nnotes"
	blk, ok := ParseUserDataBlock(desc)
	require.True(t, ok)
	assert.True(t, blk.Templated)
	assert.Equal(t, "worker", blk.SecretSet)
	assert.Equal(t, "version: v1alpha1\ntoken: {{ secret \"token\" }}\n---\nkind: Foo", blk.Content)
}

func TestParseUserDataBlock_SecretsWhitespaceAndCRLF(t *testing.T) {
	desc := "<!--#user-data \t secrets=worker  \r\nmachine: {}\r\n-->"
	blk, ok := ParseUserDataBlock(desc)
	require.True(t, ok)
	assert.True(t, blk.Templated)
	assert.Equal(t, "worker", blk.SecretSet)
	assert.Equal(t, "machine: {}", blk.Content)
}

func TestParseUserDataBlock_InvalidSetNameStillTemplated(t *testing.T) {
	// The raw value is returned unvalidated so that the caller can reject it
	// (fail closed) instead of serving the template as plain user-data.
	for _, set := range []string{"", "../other", "a/b", "x%2Fy"} {
		blk, ok := ParseUserDataBlock("<!--#user-data secrets=" + set + "\nmachine: {}\n-->")
		require.True(t, ok, set)
		assert.True(t, blk.Templated, set)
		assert.Equal(t, set, blk.SecretSet)
	}
}

func TestParseUserDataBlock_SecretsEmptyBody(t *testing.T) {
	_, ok := ParseUserDataBlock("<!--#user-data secrets=worker\n   \n-->")
	assert.False(t, ok)
}

func TestParseUserDataBlock_NoBlock(t *testing.T) {
	_, ok := ParseUserDataBlock("plain notes")
	assert.False(t, ok)
	_, ok = ParseUserDataBlock("<!--#user-data secrets=worker\nmachine: {}\n")
	assert.False(t, ok)
}

func TestParseUserDataBlock_FollowedByNetworkConfig(t *testing.T) {
	desc := "<!--#user-data secrets=worker\nmachine: {}\n-->\n<!--#network-config\nnetwork:\n  version: 2\n-->"
	blk, ok := ParseUserDataBlock(desc)
	require.True(t, ok)
	assert.Equal(t, "machine: {}", blk.Content)
	nc, ok := ParseNetworkConfig(desc)
	require.True(t, ok)
	assert.Equal(t, "network:\n  version: 2", nc)
}
