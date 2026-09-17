// SPDX-License-Identifier: AGPL-3.0-or-later

package adminapi

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
)

type recSink struct {
	mu        sync.Mutex
	snapshots [][]catalog.Target
}

func (r *recSink) IngestSnapshot(_ context.Context, _ string, ts []catalog.Target) {
	r.mu.Lock()
	cp := make([]catalog.Target, len(ts))
	copy(cp, ts)
	r.snapshots = append(r.snapshots, cp)
	r.mu.Unlock()
}
func (r *recSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.snapshots)
}

func tgt(id, addr string) catalog.Target {
	return catalog.Target{ID: id, Protocol: catalog.ProtoSSH, Address: addr}
}

func TestProvider_NameIsAdminAPI(t *testing.T) {
	p := New(nil)
	if got := p.Name(); got != "admin-api" {
		t.Errorf("Name() = %q, want admin-api", got)
	}
}

func TestProvider_CreateThenDiscover(t *testing.T) {
	sink := &recSink{}
	p := New(sink)
	ctx := context.Background()
	if err := p.Create(ctx, tgt("a", "10.0.0.1:22"), "alice"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, _ := p.Discover(ctx)
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("Discover = %+v, want one target id=a", got)
	}
	if sink.count() != 1 {
		t.Errorf("sink notifications = %d, want 1 (Create should push)", sink.count())
	}
}

func TestProvider_CreateRejectsDuplicate(t *testing.T) {
	p := New(nil)
	ctx := context.Background()
	_ = p.Create(ctx, tgt("a", "10.0.0.1:22"), "alice")
	err := p.Create(ctx, tgt("a", "10.0.0.2:22"), "alice")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestProvider_CreateRejectsEmptyID(t *testing.T) {
	p := New(nil)
	err := p.Create(context.Background(), catalog.Target{Address: "x"}, "alice")
	if err == nil {
		t.Fatalf("expected error on empty ID")
	}
}

func TestProvider_UpdateChangesAddress(t *testing.T) {
	sink := &recSink{}
	p := New(sink)
	ctx := context.Background()
	_ = p.Create(ctx, tgt("a", "10.0.0.1:22"), "alice")
	err := p.Update(ctx, "a", tgt("a", "10.0.0.99:22"), "bob")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := p.Discover(ctx)
	if got[0].Address != "10.0.0.99:22" {
		t.Errorf("address after update = %q, want 10.0.0.99:22", got[0].Address)
	}
	_, lastBy, _, _ := p.Get("a")
	if lastBy != "bob" {
		t.Errorf("last-toucher = %q, want bob", lastBy)
	}
}

func TestProvider_UpdatePinsID(t *testing.T) {
	// Operator tries to rename a target by PATCH; the provider MUST
	// keep the original id (renames would break grant_id references).
	p := New(nil)
	ctx := context.Background()
	_ = p.Create(ctx, tgt("a", "10.0.0.1:22"), "alice")
	err := p.Update(ctx, "a", catalog.Target{ID: "renamed", Address: "10.0.0.1:22"}, "alice")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := p.Discover(ctx)
	if got[0].ID != "a" {
		t.Errorf("ID after Update with bogus body.id = %q, want a (rename rejected)", got[0].ID)
	}
}

func TestProvider_UpdateRejectsMissing(t *testing.T) {
	p := New(nil)
	err := p.Update(context.Background(), "nope", tgt("nope", "x"), "alice")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestProvider_DeleteRemovesEntry(t *testing.T) {
	p := New(nil)
	ctx := context.Background()
	_ = p.Create(ctx, tgt("a", "x"), "alice")
	if err := p.Delete(ctx, "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ := p.Discover(ctx)
	if len(got) != 0 {
		t.Errorf("post-delete Discover = %+v, want empty", got)
	}
}

func TestProvider_DeleteIdempotentlyFailsMissing(t *testing.T) {
	p := New(nil)
	err := p.Delete(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestProvider_ListWithMetaSurfacesAuthor(t *testing.T) {
	p := New(nil)
	ctx := context.Background()
	_ = p.Create(ctx, tgt("a", "x"), "alice")
	_ = p.Create(ctx, tgt("b", "y"), "bob")
	rows := p.ListWithMeta()
	if len(rows) != 2 {
		t.Fatalf("entries = %d, want 2", len(rows))
	}
	byID := map[string]Entry{}
	for _, r := range rows {
		byID[r.Target.ID] = r
	}
	if byID["a"].AddedBy != "alice" || byID["b"].AddedBy != "bob" {
		t.Errorf("AddedBy attribution lost: %+v", rows)
	}
}

func TestProvider_SinkNilIsHarmless(t *testing.T) {
	// Provider with nil Sink — Create/Update/Delete must not panic;
	// the Aggregator's cron Discover() still picks up changes.
	p := New(nil)
	ctx := context.Background()
	if err := p.Create(ctx, tgt("a", "x"), "alice"); err != nil {
		t.Fatalf("nil-sink Create panicked or errored: %v", err)
	}
	got, _ := p.Discover(ctx)
	if len(got) != 1 {
		t.Errorf("post-Create Discover = %+v, want 1 target", got)
	}
}
