// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"context"
	"fmt"
	"sync"
)

// MemoryCatalog is an in-memory target registry (ADR 0030 Phase 5a). Later
// backed by a CRD/config/DB; the interface stays the same.
type MemoryCatalog struct {
	mu   sync.RWMutex
	byID map[string]*Target
}

// NewMemoryCatalog seeds a catalog with the given targets.
func NewMemoryCatalog(targets ...*Target) *MemoryCatalog {
	c := &MemoryCatalog{byID: make(map[string]*Target, len(targets))}
	for _, t := range targets {
		c.byID[t.ID] = t
	}
	return c
}

// Lookup returns the target by ID.
func (c *MemoryCatalog) Lookup(ctx context.Context, id string) (*Target, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.byID[id]
	if !ok {
		return nil, fmt.Errorf("catalog: unknown target %q", id)
	}
	return t, nil
}

// List returns targets in a region ("" = all regions).
func (c *MemoryCatalog) List(ctx context.Context, region string) ([]*Target, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Target, 0, len(c.byID))
	for _, t := range c.byID {
		if region == "" || t.Region == region {
			out = append(out, t)
		}
	}
	return out, nil
}
