package s3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/wyattanderson/pve-imds/internal/config"
	"github.com/wyattanderson/pve-imds/internal/secrets"
)

// Fields of the credentials entry in OpenBao, named like the output of
// radosgw-admin.
const (
	FieldAccessKey = "access_key"
	FieldSecretKey = "secret_key"
)

// credentialsTTL is how long credentials read from OpenBao are reused, so
// that rotated keys take effect without a restart.
const credentialsTTL = 5 * time.Minute

// CredentialSource returns the current credentials.
type CredentialSource interface {
	Credentials(ctx context.Context) (Credentials, error)
}

// KVReader reads a KV v2 entry. *secrets.KVClient implements it.
type KVReader interface {
	Read(ctx context.Context, path string) (map[string]any, error)
}

// KVCredentials reads credentials from a KV v2 entry and reuses them for a
// few minutes. Errors are never cached; concurrent reads share one request.
type KVCredentials struct {
	kv   KVReader
	path string
	ttl  time.Duration
	now  func() time.Time

	group singleflight.Group

	mu      sync.Mutex
	cached  Credentials
	expires time.Time
}

// NewKVCredentials returns a KVCredentials reading the entry at path, the
// API path below /v1/ (e.g. "kv/data/pve-imds/rgw-images").
func NewKVCredentials(kv KVReader, path string) *KVCredentials {
	return &KVCredentials{kv: kv, path: path, ttl: credentialsTTL, now: time.Now}
}

// Credentials implements [CredentialSource].
func (k *KVCredentials) Credentials(ctx context.Context) (Credentials, error) {
	k.mu.Lock()
	if k.cached.AccessKeyID != "" && k.now().Before(k.expires) {
		c := k.cached
		k.mu.Unlock()
		return c, nil
	}
	k.mu.Unlock()

	v, err, _ := k.group.Do("creds", func() (any, error) {
		data, err := k.kv.Read(ctx, k.path)
		if err != nil {
			return nil, fmt.Errorf("s3: read credentials: %w", err)
		}
		access, _ := data[FieldAccessKey].(string)
		secret, _ := data[FieldSecretKey].(string)
		if access == "" || secret == "" {
			return nil, fmt.Errorf("s3: credentials at %s need string fields %s and %s", k.path, FieldAccessKey, FieldSecretKey)
		}
		c := Credentials{AccessKeyID: access, SecretAccessKey: secret}
		k.mu.Lock()
		k.cached, k.expires = c, k.now().Add(k.ttl)
		k.mu.Unlock()
		return c, nil
	})
	if err != nil {
		return Credentials{}, err
	}
	return v.(Credentials), nil
}

// BucketOptions configures a [Bucket].
type BucketOptions struct {
	// URL is the bucket's https URL ending in "/", path style
	// (https://rgw.example.com/bucket/) or virtual-host style
	// (https://bucket.rgw.example.com/).
	URL string
	// Region is the SigV4 region. Empty means "default".
	Region string
	// Credentials supplies the access keys.
	Credentials CredentialSource
	// URLLifetime is how long a presigned URL is valid.
	URLLifetime time.Duration
}

// Bucket signs requests for objects below one bucket URL.
type Bucket struct {
	prefix   string
	region   string
	creds    CredentialSource
	lifetime time.Duration
	now      func() time.Time
}

// NewBucket validates opts and returns a Bucket.
func NewBucket(opts BucketOptions) (*Bucket, error) {
	if err := ValidateBucketURL(opts.URL); err != nil {
		return nil, err
	}
	if opts.Credentials == nil {
		return nil, errors.New("s3: no credential source")
	}
	if opts.URLLifetime < time.Second || opts.URLLifetime > MaxPresignExpiry {
		return nil, fmt.Errorf("s3: url_lifetime %s must be between 1s and %s", opts.URLLifetime, MaxPresignExpiry)
	}
	region := opts.Region
	if region == "" {
		region = "default"
	}
	return &Bucket{prefix: opts.URL, region: region, creds: opts.Credentials, lifetime: opts.URLLifetime, now: time.Now}, nil
}

// ValidateBucketURL returns an error unless raw is an https URL with a
// host, without user info, query or fragment, ending in "/".
func ValidateBucketURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("s3: bucket_url %q must be an https URL without query or user info", raw)
	}
	if !strings.HasSuffix(raw, "/") {
		return fmt.Errorf("s3: bucket_url %q must end with /", raw)
	}
	return nil
}

// URL returns the bucket URL; every object URL starts with it.
func (b *Bucket) URL() string { return b.prefix }

// Contains reports whether rawURL is an object in the bucket.
func (b *Bucket) Contains(rawURL string) bool {
	return strings.HasPrefix(rawURL, b.prefix) && len(rawURL) > len(b.prefix)
}

// object parses rawURL and checks that it is in the bucket.
func (b *Bucket) object(rawURL string) (*url.URL, error) {
	if !b.Contains(rawURL) {
		return nil, fmt.Errorf("s3: %q is not an object in %s", rawURL, b.prefix)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("s3: parse object url: %w", err)
	}
	return u, nil
}

// PresignGet returns a presigned GET URL for the object at rawURL, valid
// for the configured lifetime. The result carries a signature; never log
// it.
func (b *Bucket) PresignGet(ctx context.Context, rawURL string) (string, error) {
	u, err := b.object(rawURL)
	if err != nil {
		return "", err
	}
	c, err := b.creds.Credentials(ctx)
	if err != nil {
		return "", err
	}
	return Presign(http.MethodGet, u, c, b.region, b.now(), b.lifetime)
}

// SignRequest signs req, a request for an object in the bucket, with an
// unsigned payload.
func (b *Bucket) SignRequest(ctx context.Context, req *http.Request) error {
	if _, err := b.object(req.URL.String()); err != nil {
		return err
	}
	c, err := b.creds.Credentials(ctx)
	if err != nil {
		return err
	}
	SignRequest(req, c, b.region, UnsignedPayload, b.now())
	return nil
}

// FromConfig returns the image bucket configured in cfg, reading its
// credentials with the OpenBao connection settings of conn. It returns
// (nil, nil) when cfg.BucketURL is empty.
func FromConfig(cfg config.PXEImagesConfig, conn config.SecretsConfig) (*Bucket, error) {
	if cfg.BucketURL == "" {
		return nil, nil
	}
	if cfg.CredentialsPath == "" {
		return nil, errors.New("s3: pxe.images.credentials_path is required")
	}
	if conn.Address == "" || conn.TokenFile == "" {
		return nil, errors.New("s3: pxe.images requires secrets.address and secrets.token_file")
	}
	kv, err := secrets.NewKVClient(secrets.ConnOptions{
		Address:   conn.Address,
		Namespace: conn.Namespace,
		CAFile:    conn.CAFile,
		TokenFile: conn.TokenFile,
	})
	if err != nil {
		return nil, err
	}
	return NewBucket(BucketOptions{
		URL:         cfg.BucketURL,
		Region:      cfg.Region,
		Credentials: NewKVCredentials(kv, cfg.CredentialsPath),
		URLLifetime: cfg.URLLifetime,
	})
}
