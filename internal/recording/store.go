// SPDX-License-Identifier: AGPL-3.0-or-later

package recording

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ObjectStore persists recording artifacts. PRODUCTION is MinIO/S3 with Object
// Lock (compliance mode, 7-yr retention) so objects are immutable WORM. FSStore
// is the dev/test implementation (a directory tree; no WORM enforcement).
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// ObjectLister is an optional capability: enumerate object keys under a prefix.
// Both FSStore and S3Store implement it. The recordings list endpoint (ADR 0051
// P4 replay) uses it to discover sealed bundles (it scans for `<id>/manifest.json`
// keys); a store that doesn't implement it simply yields no listing (the SPA then
// degrades to "listing unavailable").
type ObjectLister interface {
	// List returns object keys under prefix (recursive). Order is unspecified.
	List(ctx context.Context, prefix string) ([]string, error)
}

// FSStore writes objects under a directory (dev/test only — NOT WORM).
type FSStore struct{ dir string }

// NewFSStore roots a filesystem store at dir.
func NewFSStore(dir string) *FSStore { return &FSStore{dir: dir} }

func (s *FSStore) path(key string) string {
	// Contain the key within dir (defend against traversal via ".." / leading /).
	clean := filepath.Clean("/" + key)
	return filepath.Join(s.dir, clean)
}

func (s *FSStore) Put(ctx context.Context, key string, data []byte) error {
	p := s.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("recording: mkdir: %w", err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("recording: write %s: %w", key, err)
	}
	return nil
}

func (s *FSStore) Get(ctx context.Context, key string) ([]byte, error) {
	return os.ReadFile(s.path(key))
}

// List walks the store tree under prefix and returns the relative object keys
// (forward-slash separated, matching the Put/Get key shape).
func (s *FSStore) List(ctx context.Context, prefix string) ([]string, error) {
	base := s.path(prefix)
	var keys []string
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return fs.SkipDir // empty store / missing prefix → no keys
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(s.dir, p)
		if rerr != nil {
			return rerr
		}
		keys = append(keys, filepath.ToSlash(rel))
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("recording: list %q: %w", prefix, err)
	}
	return keys, nil
}

// manifestSuffix is the per-session manifest key suffix the list endpoint scans
// for (SessionsFrom turns matching keys into session ids).
const manifestSuffix = "/manifest.json"

// SessionsFrom returns the unique session ids implied by a set of object keys
// (those ending in /manifest.json). Helper for list endpoints.
func SessionsFrom(keys []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, k := range keys {
		if strings.HasSuffix(k, manifestSuffix) {
			id := strings.TrimSuffix(k, manifestSuffix)
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				out = append(out, id)
			}
		}
	}
	return out
}
