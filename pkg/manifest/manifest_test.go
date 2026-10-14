package manifest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	talosPrefix = "https://pxe.factory.talos.dev/pxe/"
	talosURL    = talosPrefix + "376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba/v1.14.2/nocloud-amd64-secureboot"
	sha         = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
)

var opts = Options{ChainAllowedPrefixes: []string{talosPrefix}}

func TestParseValid(t *testing.T) {
	m, skipped, err := Parse([]byte(`{
	  "images": {
	    "debian13": {
	      "type": "disk",
	      "latest": "2026.10.01",
	      "versions": {
	        "2026.10.01": {"url": "https://rgw.example.com/pxe/debian13/2026.10.01.raw.zst", "sha256": "`+strings.ToUpper(sha)+`", "size": 123456789}
	      }
	    },
	    "talos": {
	      "type": "chain",
	      "latest": "v1.14.2",
	      "versions": {"v1.14.2": {"url": "`+talosURL+`"}}
	    },
	    "netboot": {
	      "type": "chain",
	      "boot": "always",
	      "latest": "1",
	      "versions": {"1": {"url": "`+talosPrefix+`x"}}
	    }
	  }
	}`), opts)
	require.NoError(t, err)
	assert.Empty(t, skipped)
	assert.Equal(t, map[string]Image{
		"debian13": {
			Type:   TypeDisk,
			Latest: "2026.10.01",
			Versions: map[string]Version{
				"2026.10.01": {URL: "https://rgw.example.com/pxe/debian13/2026.10.01.raw.zst", SHA256: sha, Size: 123456789},
			},
		},
		"talos": {
			Type:     TypeChain,
			Boot:     BootOnce,
			Latest:   "v1.14.2",
			Versions: map[string]Version{"v1.14.2": {URL: talosURL}},
		},
		"netboot": {
			Type:     TypeChain,
			Boot:     BootAlways,
			Latest:   "1",
			Versions: map[string]Version{"1": {URL: talosPrefix + "x"}},
		},
	}, m.Images)
}

func TestParseInvalidDocument(t *testing.T) {
	for _, doc := range []string{
		``,
		`[]`,
		`{"images": []}`,
		`{}`,
		`{"images": {}, "extra": 1}`,
		`{"images": {}} {}`,
		`{"images": {`,
	} {
		_, _, err := Parse([]byte(doc), opts)
		assert.Error(t, err, doc)
	}
}

func TestParseSkipsInvalidEntries(t *testing.T) {
	disk := func(versions string) string {
		return `{"type": "disk", "latest": "1", "versions": {` + versions + `}}`
	}
	good := `"1": {"url": "https://rgw.example.com/a.raw.zst", "sha256": "` + sha + `", "size": 1}`

	cases := []struct {
		name  string
		image string // JSON of the "img" entry
		// skipVersion is the version reported as skipped, if the image
		// itself survives.
		skipVersion string
		keepImage   bool
	}{
		{name: "unknown type", image: `{"type": "iso", "latest": "1", "versions": {` + good + `}}`},
		{name: "unknown image key", image: `{"type": "disk", "latest": "1", "kernel": "x", "versions": {` + good + `}}`},
		{name: "boot on disk", image: `{"type": "disk", "boot": "once", "latest": "1", "versions": {` + good + `}}`},
		{name: "bad boot", image: `{"type": "chain", "boot": "sometimes", "latest": "1", "versions": {"1": {"url": "` + talosURL + `"}}}`},
		{name: "missing latest", image: `{"type": "disk", "versions": {` + good + `}}`},
		{name: "latest not in versions", image: `{"type": "disk", "latest": "2", "versions": {` + good + `}}`},
		{name: "http url", image: disk(`"1": {"url": "http://rgw.example.com/a.raw.zst", "sha256": "` + sha + `", "size": 1}`)},
		{name: "url with ipxe variable", image: disk(`"1": {"url": "https://rgw.example.com/${net0/mac}.raw.zst", "sha256": "` + sha + `", "size": 1}`)},
		{name: "url with space", image: disk(`"1": {"url": "https://rgw.example.com/a b", "sha256": "` + sha + `", "size": 1}`)},
		{name: "url with user info", image: disk(`"1": {"url": "https://u:p@rgw.example.com/a", "sha256": "` + sha + `", "size": 1}`)},
		{name: "short sha256", image: disk(`"1": {"url": "https://rgw.example.com/a", "sha256": "abc", "size": 1}`)},
		{name: "non-hex sha256", image: disk(`"1": {"url": "https://rgw.example.com/a", "sha256": "` + strings.Repeat("g", 64) + `", "size": 1}`)},
		{name: "zero size", image: disk(`"1": {"url": "https://rgw.example.com/a", "sha256": "` + sha + `", "size": 0}`)},
		{name: "missing size", image: disk(`"1": {"url": "https://rgw.example.com/a", "sha256": "` + sha + `"}`)},
		{name: "unknown version key", image: disk(`"1": {"url": "https://rgw.example.com/a", "sha256": "` + sha + `", "size": 1, "kernel": "x"}`)},
		{name: "chain not allowed", image: `{"type": "chain", "latest": "1", "versions": {"1": {"url": "https://evil.example.com/pxe/x"}}}`},
		{name: "chain prefix without slash boundary", image: `{"type": "chain", "latest": "1", "versions": {"1": {"url": "https://pxe.factory.talos.dev/pxe-evil/x"}}}`},
		{name: "chain traversal", image: `{"type": "chain", "latest": "1", "versions": {"1": {"url": "` + talosPrefix + `../../evil"}}}`},
		{name: "chain encoded traversal", image: `{"type": "chain", "latest": "1", "versions": {"1": {"url": "` + talosPrefix + `%2e%2e/evil"}}}`},
		{name: "chain with sha256", image: `{"type": "chain", "latest": "1", "versions": {"1": {"url": "` + talosURL + `", "sha256": "` + sha + `"}}}`},
		{
			name:        "invalid old version is dropped",
			image:       disk(good + `, "0": {"url": "https://rgw.example.com/a", "sha256": "x", "size": 1}`),
			skipVersion: "0",
			keepImage:   true,
		},
		{
			name:        "invalid version name is dropped",
			image:       disk(good + `, "V2": {"url": "https://rgw.example.com/a", "sha256": "` + sha + `", "size": 1}`),
			skipVersion: "V2",
			keepImage:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"images": {"img": ` + tc.image + `, "ok": ` + disk(good) + `}}`
			m, skipped, err := Parse([]byte(doc), opts)
			require.NoError(t, err)
			require.NotEmpty(t, skipped)
			assert.Contains(t, m.Images, "ok", "valid entries are kept")

			if tc.keepImage {
				require.Contains(t, m.Images, "img")
				assert.NotContains(t, m.Images["img"].Versions, tc.skipVersion)
				assert.Equal(t, []Skipped{{Image: "img", Version: tc.skipVersion, Reason: skipped[0].Reason}}, skipped)
			} else {
				assert.NotContains(t, m.Images, "img")
				assert.Equal(t, "img", skipped[len(skipped)-1].Image)
				assert.Empty(t, skipped[len(skipped)-1].Version)
			}
		})
	}
}

func TestParseDiskURLPrefix(t *testing.T) {
	doc := `{"images": {
	  "in": {"type": "disk", "latest": "1", "versions": {"1": {"url": "https://rgw.example.com/pxe-images/in/1.raw.zst", "sha256": "` + sha + `", "size": 1}}},
	  "sibling": {"type": "disk", "latest": "1", "versions": {"1": {"url": "https://rgw.example.com/pxe-images-old/1.raw.zst", "sha256": "` + sha + `", "size": 1}}},
	  "talos": {"type": "chain", "latest": "1", "versions": {"1": {"url": "` + talosURL + `"}}}
	}}`
	o := opts
	o.DiskURLPrefix = "https://rgw.example.com/pxe-images/"
	m, skipped, err := Parse([]byte(doc), o)
	require.NoError(t, err)
	assert.Contains(t, m.Images, "in")
	assert.Contains(t, m.Images, "talos", "chain images are not restricted to the bucket")
	assert.NotContains(t, m.Images, "sibling")
	require.Len(t, skipped, 2)
	assert.Contains(t, skipped[0].Reason, "is not below")
}

func TestParseInvalidImageID(t *testing.T) {
	m, skipped, err := Parse([]byte(`{"images": {"Debian": {"type": "disk", "latest": "1", "versions": {}}}}`), opts)
	require.NoError(t, err)
	assert.Empty(t, m.Images)
	assert.Len(t, skipped, 1)
}

func TestValidateAllowedPrefixes(t *testing.T) {
	require.NoError(t, ValidateAllowedPrefixes(nil))
	require.NoError(t, ValidateAllowedPrefixes([]string{talosPrefix, "https://boot.example.com/"}))
	for _, p := range []string{
		"http://pxe.factory.talos.dev/pxe/",
		"https://pxe.factory.talos.dev/pxe",
		"https:///pxe/",
		"pxe.factory.talos.dev/pxe/",
	} {
		assert.Error(t, ValidateAllowedPrefixes([]string{p}), p)
	}
}
