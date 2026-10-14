package s3

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/pve-imds/internal/config"
)

type fakeKV struct {
	mu    sync.Mutex
	data  map[string]any
	err   error
	reads int
}

func (f *fakeKV) Read(_ context.Context, path string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return nil, f.err
	}
	if path != "kv/data/pve-imds/rgw-images" {
		return nil, errors.New("wrong path " + path)
	}
	return f.data, nil
}

func newKV() *fakeKV {
	return &fakeKV{data: map[string]any{FieldAccessKey: "AK", FieldSecretKey: "SK"}}
}

func TestKVCredentialsCachesAndRefreshes(t *testing.T) {
	kv := newKV()
	c := NewKVCredentials(kv, "kv/data/pve-imds/rgw-images")
	now := time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	ctx := context.Background()

	got, err := c.Credentials(ctx)
	require.NoError(t, err)
	assert.Equal(t, Credentials{AccessKeyID: "AK", SecretAccessKey: "SK"}, got)
	_, err = c.Credentials(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, kv.reads, "reused within the TTL")

	// Rotated keys are picked up once the TTL has passed.
	kv.data = map[string]any{FieldAccessKey: "AK2", FieldSecretKey: "SK2"}
	now = now.Add(credentialsTTL)
	got, err = c.Credentials(ctx)
	require.NoError(t, err)
	assert.Equal(t, "AK2", got.AccessKeyID)
	assert.Equal(t, 2, kv.reads)
}

func TestKVCredentialsErrors(t *testing.T) {
	kv := newKV()
	kv.err = errors.New("bao down")
	c := NewKVCredentials(kv, "kv/data/pve-imds/rgw-images")
	_, err := c.Credentials(context.Background())
	require.ErrorContains(t, err, "bao down")

	// Errors are not cached.
	kv.err = nil
	_, err = c.Credentials(context.Background())
	require.NoError(t, err)

	for name, data := range map[string]map[string]any{
		"missing secret":    {FieldAccessKey: "AK"},
		"empty access key":  {FieldAccessKey: "", FieldSecretKey: "SK"},
		"non-string secret": {FieldAccessKey: "AK", FieldSecretKey: 1},
	} {
		t.Run(name, func(t *testing.T) {
			c := NewKVCredentials(&fakeKV{data: data}, "kv/data/pve-imds/rgw-images")
			_, err := c.Credentials(context.Background())
			require.ErrorContains(t, err, "access_key and secret_key")
		})
	}
}

func newBucket(t *testing.T, kv *fakeKV) *Bucket {
	t.Helper()
	b, err := NewBucket(BucketOptions{
		URL:         "https://rgw.example.com/pxe-images/",
		Credentials: NewKVCredentials(kv, "kv/data/pve-imds/rgw-images"),
		URLLifetime: 15 * time.Minute,
	})
	require.NoError(t, err)
	b.now = func() time.Time { return time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC) }
	return b
}

func TestBucketPresignGet(t *testing.T) {
	b := newBucket(t, newKV())
	got, err := b.PresignGet(context.Background(), "https://rgw.example.com/pxe-images/debian13/2026.10.14.raw.zst")
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	assert.Equal(t, "/pxe-images/debian13/2026.10.14.raw.zst", u.Path)
	q := u.Query()
	assert.Equal(t, "AK/20261014/default/s3/aws4_request", q.Get("X-Amz-Credential"))
	assert.Equal(t, "20261014T180000Z", q.Get("X-Amz-Date"))
	assert.Equal(t, "900", q.Get("X-Amz-Expires"))
	assert.Len(t, q.Get("X-Amz-Signature"), 64)
	assert.NotContains(t, got, "SK", "the secret never appears in the URL")
}

func TestBucketRejectsObjectsOutsideTheBucket(t *testing.T) {
	kv := newKV()
	b := newBucket(t, kv)
	for _, raw := range []string{
		"https://rgw.example.com/pxe-images/",
		"https://rgw.example.com/pxe-images-old/x.raw.zst",
		"https://rgw.example.com/other/x.raw.zst",
		"https://evil.example.com/pxe-images/x.raw.zst",
	} {
		_, err := b.PresignGet(context.Background(), raw)
		require.ErrorContains(t, err, "is not an object in", raw)

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
		require.Error(t, b.SignRequest(context.Background(), req), raw)
		assert.Empty(t, req.Header.Get("Authorization"))
	}
	assert.Zero(t, kv.reads, "no credentials are read for a rejected object")
}

func TestBucketSignRequest(t *testing.T) {
	b := newBucket(t, newKV())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://rgw.example.com/pxe-images/manifest.json", nil)
	require.NoError(t, err)
	require.NoError(t, b.SignRequest(context.Background(), req))
	assert.Equal(t, UnsignedPayload, req.Header.Get("X-Amz-Content-Sha256"))
	assert.True(t, strings.HasPrefix(req.Header.Get("Authorization"),
		"AWS4-HMAC-SHA256 Credential=AK/20261014/default/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="),
		req.Header.Get("Authorization"))

	kv := newKV()
	kv.err = errors.New("bao down")
	b = newBucket(t, kv)
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "https://rgw.example.com/pxe-images/manifest.json", nil)
	require.ErrorContains(t, b.SignRequest(context.Background(), req), "bao down")
}

func TestValidateBucketURL(t *testing.T) {
	require.NoError(t, ValidateBucketURL("https://rgw.example.com/pxe-images/"))
	require.NoError(t, ValidateBucketURL("https://pxe-images.rgw.example.com/"))
	for _, raw := range []string{
		"",
		"http://rgw.example.com/pxe-images/",
		"https://rgw.example.com/pxe-images",
		"https://u:p@rgw.example.com/pxe-images/",
		"https://rgw.example.com/pxe-images/?x=1",
		"https:///pxe-images/",
	} {
		assert.Error(t, ValidateBucketURL(raw), raw)
	}
}

func TestFromConfig(t *testing.T) {
	conn := config.SecretsConfig{Address: "https://bao:8200", TokenFile: "/run/token"}
	cfg := config.Default().PXE.Images

	b, err := FromConfig(cfg, conn)
	require.NoError(t, err)
	assert.Nil(t, b, "no bucket_url, no bucket")

	cfg.BucketURL = "https://rgw.example.com/pxe-images/"
	b, err = FromConfig(cfg, conn)
	require.NoError(t, err)
	assert.Equal(t, "default", b.region)
	assert.Equal(t, 15*time.Minute, b.lifetime)

	c := cfg
	c.CredentialsPath = ""
	_, err = FromConfig(c, conn)
	require.ErrorContains(t, err, "credentials_path")

	_, err = FromConfig(cfg, config.SecretsConfig{})
	require.ErrorContains(t, err, "secrets.address")
}
