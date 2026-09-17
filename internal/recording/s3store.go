// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Store is the PRODUCTION ObjectStore: MinIO/S3 with Object Lock so every
// recording artifact is immutable WORM for the retention window (the 7-yr
// audit-archive bucket). The bucket MUST have Object Lock enabled at creation;
// Put then stamps a per-object retain-until date in the configured mode
// (COMPLIANCE = not even root can delete before expiry; GOVERNANCE = a
// privileged bypass exists). Distinct from FSStore (dev, no WORM).
type S3Store struct {
	client    *minio.Client
	bucket    string
	retention time.Duration
	mode      minio.RetentionMode
}

// S3Config configures an S3Store.
type S3Config struct {
	Endpoint  string // host:port (no scheme)
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
	Retention time.Duration // per-object lock window (e.g. 7*365*24h)
	Mode      string        // "COMPLIANCE" (default) or "GOVERNANCE"
	Region    string        // optional
}

// NewS3Store builds a MinIO-backed WORM object store.
func NewS3Store(cfg S3Config) (*S3Store, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("recording: S3 endpoint and bucket required")
	}
	cl, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("recording: minio client: %w", err)
	}
	mode := minio.Compliance
	if cfg.Mode == "GOVERNANCE" {
		mode = minio.Governance
	}
	ret := cfg.Retention
	if ret == 0 {
		ret = 7 * 365 * 24 * time.Hour // 7-yr default (matches audit-archive policy)
	}
	return &S3Store{client: cl, bucket: cfg.Bucket, retention: ret, mode: mode}, nil
}

// Put writes data under key with an Object-Lock retain-until date. Re-Putting an
// existing key fails under COMPLIANCE (WORM) — recording keys are unique per
// session (recorded once), so this is the intended immutability.
func (s *S3Store) Put(ctx context.Context, key string, data []byte) error {
	retainUntil := time.Now().UTC().Add(s.retention)
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{
			ContentType:     "application/octet-stream",
			Mode:            s.mode,
			RetainUntilDate: retainUntil,
		})
	if err != nil {
		return fmt.Errorf("recording: s3 put %s: %w", key, err)
	}
	return nil
}

// Get reads an object back (for verification / replay).
func (s *S3Store) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("recording: s3 get %s: %w", key, err)
	}
	defer obj.Close()
	return io.ReadAll(obj)
}

// List returns the object keys under prefix (recursive) — used by the recordings
// list endpoint to discover sealed bundles. ListObjects streams keys lazily.
func (s *S3Store) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("recording: s3 list %q: %w", prefix, obj.Err)
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}
