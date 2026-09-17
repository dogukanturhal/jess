// SPDX-License-Identifier: AGPL-3.0-or-later

package caep

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// FileTokenSource reads a Bearer token from disk on every Token()
// call. Designed for the talon!63-style sidecar pattern: a sidecar
// container refreshes the token to a shared volume; this consumer
// rereads on every connect attempt so a refresh propagates within
// one reconnect-backoff cycle (worst case ~30s).
//
// Whitespace + newlines are trimmed so the file can be written by
// a shell-redirect (echo > file) or a Vault-agent template.
type FileTokenSource struct {
	Path string
}

func (s FileTokenSource) Token(_ context.Context) (string, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return "", fmt.Errorf("caep: read token file %s: %w", s.Path, err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("caep: token file %s is empty", s.Path)
	}
	return t, nil
}

// StaticTokenSource returns the same token on every call. Test-only.
type StaticTokenSource struct {
	Tok string
}

func (s StaticTokenSource) Token(_ context.Context) (string, error) {
	if s.Tok == "" {
		return "", fmt.Errorf("caep: static token is empty")
	}
	return s.Tok, nil
}
