// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package s3 signs S3 requests for objects in one private bucket, such as a
// Ceph RGW bucket that holds disk images. It implements just enough AWS
// Signature Version 4 for unauthenticated-payload GETs: signing a request's
// headers, and presigning a URL that someone else fetches. Signing is pure
// computation; the package never transfers object data.
package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	algorithm = "AWS4-HMAC-SHA256"
	service   = "s3"
	// amzDateFormat is the ISO 8601 basic format SigV4 uses.
	amzDateFormat = "20060102T150405Z"

	// UnsignedPayload is the payload hash of a request whose body is not
	// signed.
	UnsignedPayload = "UNSIGNED-PAYLOAD"

	// MaxPresignExpiry is the longest lifetime S3 accepts for a presigned
	// URL.
	MaxPresignExpiry = 7 * 24 * time.Hour
)

// Credentials are an S3 access key pair.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

// SignRequest adds a SigV4 Authorization header to req. It signs the Host
// and every header already set on req, and sets X-Amz-Date and
// X-Amz-Content-Sha256 (payloadHash, e.g. [UnsignedPayload]) first. Headers
// that the HTTP client adds later, such as User-Agent, are not signed.
func SignRequest(req *http.Request, c Credentials, region, payloadHash string, now time.Time) {
	now = now.UTC()
	req.Header.Set("X-Amz-Date", now.Format(amzDateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, v := range req.Header {
		headers[strings.ToLower(k)] = strings.Join(trimAll(v), ",")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	scope := credentialScope(now, region)
	canonReq := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL.Query()),
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	sig := signature(c.SecretAccessKey, now, region, stringToSign(now, scope, canonReq))

	req.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, c.AccessKeyID, scope, signedHeaders, sig))
}

// Presign returns u with SigV4 query authentication for method, valid for
// expires from now. Only the Host header is signed, so the URL works with
// any HTTP client. S3 checks the expiry when a request starts, so a
// download may outlast it.
func Presign(method string, u *url.URL, c Credentials, region string, now time.Time, expires time.Duration) (string, error) {
	if expires < time.Second || expires > MaxPresignExpiry {
		return "", fmt.Errorf("s3: presign expiry %s must be between 1s and %s", expires, MaxPresignExpiry)
	}
	if u.Host == "" {
		return "", errors.New("s3: presign: url has no host")
	}
	now = now.UTC()
	scope := credentialScope(now, region)

	q := u.Query()
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", c.AccessKeyID+"/"+scope)
	q.Set("X-Amz-Date", now.Format(amzDateFormat))
	q.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	q.Set("X-Amz-SignedHeaders", "host")

	query := canonicalQuery(q)
	canonReq := strings.Join([]string{
		method,
		canonicalURI(u),
		query,
		"host:" + presignHost(u) + "\n",
		"host",
		UnsignedPayload,
	}, "\n")
	sig := signature(c.SecretAccessKey, now, region, stringToSign(now, scope, canonReq))

	out := *u
	out.RawQuery = query + "&X-Amz-Signature=" + sig
	out.Fragment, out.RawFragment = "", ""
	return out.String(), nil
}

// presignHost is the Host header a client sends for u: without the
// scheme's default port, which clients such as curl leave out.
func presignHost(u *url.URL) string {
	switch u.Scheme {
	case "https":
		return strings.TrimSuffix(u.Host, ":443")
	case "http":
		return strings.TrimSuffix(u.Host, ":80")
	}
	return u.Host
}

func credentialScope(now time.Time, region string) string {
	return now.Format("20060102") + "/" + region + "/" + service + "/aws4_request"
}

func stringToSign(now time.Time, scope, canonReq string) string {
	h := sha256.Sum256([]byte(canonReq))
	return algorithm + "\n" + now.Format(amzDateFormat) + "\n" + scope + "\n" + hex.EncodeToString(h[:])
}

func signature(secret string, now time.Time, region, toSign string) string {
	k := hmacSHA256([]byte("AWS4"+secret), now.Format("20060102"))
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	return hex.EncodeToString(hmacSHA256(k, toSign))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// canonicalURI is the URI-encoded path. S3 encodes it once, keeping "/".
func canonicalURI(u *url.URL) string {
	segs := strings.Split(u.EscapedPath(), "/")
	for i, s := range segs {
		if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
		segs[i] = uriEncode(s)
	}
	p := strings.Join(segs, "/")
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQuery sorts and URI-encodes query parameters.
func canonicalQuery(q url.Values) string {
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, kv{uriEncode(k), uriEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// uriEncode percent-encodes everything but the unreserved characters, as
// SigV4 requires.
func uriEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

// trimAll trims header values and collapses inner runs of spaces.
func trimAll(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strings.Join(strings.Fields(v), " ")
	}
	return out
}
