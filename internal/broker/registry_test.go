// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"testing"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/sshproxy"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()

	if err := r.Register(nil); err == nil {
		t.Fatal("Register(nil) must error")
	}
	if err := r.Register(emptyProtoBroker{}); err == nil {
		t.Fatal("Register with empty protocol must error")
	}

	ssh := NewSSHBroker(&sshproxy.Config{}, nil)
	if err := r.Register(ssh); err != nil {
		t.Fatalf("register ssh broker: %v", err)
	}
	if err := r.Register(NewSSHBroker(&sshproxy.Config{}, nil)); err == nil {
		t.Fatal("duplicate protocol registration must error")
	}

	got, err := r.For(string(catalog.ProtoSSH))
	if err != nil {
		t.Fatalf("For(ssh): %v", err)
	}
	if got != ssh {
		t.Fatal("For(ssh) returned a different broker than was registered")
	}

	if _, err := r.For("rdp"); err == nil {
		t.Fatal("For an unregistered protocol must error (no silent fall-through)")
	}
}

type emptyProtoBroker struct{}

func (emptyProtoBroker) Protocol() string { return "" }
func (emptyProtoBroker) Mint(context.Context, AccessGrant) (Credential, error) {
	return nil, nil
}
func (emptyProtoBroker) Dial(context.Context, *Target, Credential) (RecordedConn, error) {
	return nil, nil
}
