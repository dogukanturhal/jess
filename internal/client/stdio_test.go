// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// echoUpper reads until EOF then replies, proving half-close works: the
// "controller" only answers after the client's write side is closed.
func TestPipeStdioHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c) // until client half-closes
		_, _ = c.Write(append([]byte("echo:"), b...))
	}()
	up, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- pipeStdio(context.Background(), up, bytes.NewReader([]byte("hello")), &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipeStdio did not return")
	}
	if got := out.String(); got != "echo:hello" {
		t.Fatalf("out = %q", got)
	}
}

// Server closes first while stdin is still open: must return without
// waiting for stdin.
func TestPipeStdioServerClose(t *testing.T) {
	a, b := net.Pipe()
	go func() { _, _ = b.Write([]byte("bye")); _ = b.Close() }()
	pr, pw := io.Pipe()
	defer pw.Close()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- pipeStdio(context.Background(), a, pr, &out) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pipeStdio blocked on stdin")
	}
	if out.String() != "bye" {
		t.Fatalf("out = %q", out.String())
	}
}
