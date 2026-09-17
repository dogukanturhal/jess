// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Tiny adapter wrapping catalog.Catalog as admin.CatalogLister. Keeps
// internal/admin from importing internal/catalog directly (would create
// a dep cycle the moment catalog grows admin endpoints of its own).

import (
	"context"

	"github.com/dogukanturhal/jess/internal/admin"
	"github.com/dogukanturhal/jess/internal/catalog"
)

type catalogLister struct {
	cat catalog.Catalog
}

func (c catalogLister) List(ctx context.Context, region string) ([]*admin.CatalogTarget, error) {
	ts, err := c.cat.List(ctx, region)
	if err != nil {
		return nil, err
	}
	out := make([]*admin.CatalogTarget, 0, len(ts))
	for _, t := range ts {
		out = append(out, &admin.CatalogTarget{
			ID:       t.ID,
			Name:     t.Name,
			Protocol: string(t.Protocol),
			Address:  t.Address,
			Region:   t.Region,
		})
	}
	return out, nil
}
