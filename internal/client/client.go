// SPDX-License-Identifier: AGPL-3.0-or-later

// Package client is the operator-side library for jessctl: it connects to the
// controller's operator port, presents a verified Falcon-ID token, and bridges
// a brokered session. A local proxy exposes a loopback port the operator points
// ssh/psql/etc. at (the `boundary connect` / Teleport local-proxy pattern).
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"github.com/dogukanturhal/jess/internal/wire"
)

// Dial connects to the controller's operator address, sends the request, and
// returns the connection in bridge mode (raw session bytes flow afterward). If
// tlsCfg is non-nil the link is TLS.
func Dial(ctx context.Context, controllerAddr string, tlsCfg *tls.Config, req wire.OperatorRequest) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	d := &net.Dialer{}
	if tlsCfg != nil {
		conn, err = tls.DialWithDialer(d, "tcp", controllerAddr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", controllerAddr)
	}
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(b); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("client: send request: %w", err)
	}
	return conn, nil
}

// LocalProxy listens on listenAddr and bridges each accepted local connection to
// a fresh brokered session, so the operator points a normal client (ssh, psql,
// …) at the returned local address. It serves until ctx is cancelled; the
// returned address is the actual bound address (use :0 for an ephemeral port).
func LocalProxy(ctx context.Context, listenAddr, controllerAddr string, tlsCfg *tls.Config, req wire.OperatorRequest) (string, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			local, err := ln.Accept()
			if err != nil {
				return
			}
			go bridge(ctx, local, controllerAddr, tlsCfg, req)
		}
	}()
	return ln.Addr().String(), nil
}

func bridge(ctx context.Context, local net.Conn, controllerAddr string, tlsCfg *tls.Config, req wire.OperatorRequest) {
	defer local.Close()
	up, err := Dial(ctx, controllerAddr, tlsCfg, req)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, up); done <- struct{}{} }()
	<-done
	_ = up.Close()
	_ = local.Close()
	<-done
}
