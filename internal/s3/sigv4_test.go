// SPDX-FileCopyrightText: 2026 Mateusz Nowak
// SPDX-License-Identifier: AGPL-3.0-or-later

package s3

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The example credentials and expected signatures are from the AWS S3
// SigV4 documentation.
var (
	exampleCreds = Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	exampleTime  = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestSignRequestAWSExample(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=0-9")

	SignRequest(req, exampleCreds, "us-east-1", emptySHA256, exampleTime)

	assert.Equal(t, "20130524T000000Z", req.Header.Get("X-Amz-Date"))
	assert.Equal(t, emptySHA256, req.Header.Get("X-Amz-Content-Sha256"))
	assert.Equal(t,
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "+
			"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "+
			"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		req.Header.Get("Authorization"))
}

func TestPresignAWSExample(t *testing.T) {
	u, err := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	require.NoError(t, err)

	got, err := Presign(http.MethodGet, u, exampleCreds, "us-east-1", exampleTime, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, "https://examplebucket.s3.amazonaws.com/test.txt"+
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256"+
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"+
		"&X-Amz-Date=20130524T000000Z"+
		"&X-Amz-Expires=86400"+
		"&X-Amz-SignedHeaders=host"+
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", got)
}

func TestPresignDefaultPort(t *testing.T) {
	withPort, _ := url.Parse("https://examplebucket.s3.amazonaws.com:443/test.txt")
	without, _ := url.Parse("https://examplebucket.s3.amazonaws.com/test.txt")
	a, err := Presign(http.MethodGet, withPort, exampleCreds, "us-east-1", exampleTime, time.Hour)
	require.NoError(t, err)
	b, err := Presign(http.MethodGet, without, exampleCreds, "us-east-1", exampleTime, time.Hour)
	require.NoError(t, err)
	sig := func(raw string) string {
		_, after, ok := strings.Cut(raw, "X-Amz-Signature=")
		require.True(t, ok)
		return after
	}
	assert.Equal(t, sig(b), sig(a))
}

func TestPresignExpiryBounds(t *testing.T) {
	u, _ := url.Parse("https://rgw.example.com/b/o")
	for _, d := range []time.Duration{0, 500 * time.Millisecond, MaxPresignExpiry + time.Second} {
		_, err := Presign(http.MethodGet, u, exampleCreds, "default", exampleTime, d)
		assert.Error(t, err, d)
	}
}

func TestCanonicalURI(t *testing.T) {
	for in, want := range map[string]string{
		"https://h/":                     "/",
		"https://h":                      "/",
		"https://h/b/debian13/1.raw.zst": "/b/debian13/1.raw.zst",
		"https://h/b/a%20b+c":            "/b/a%20b%2Bc",
		"https://h/b/caf%C3%A9":          "/b/caf%C3%A9",
		"https://h/b/a~b_c-d":            "/b/a~b_c-d",
	} {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.Equal(t, want, canonicalURI(u), in)
	}
}
