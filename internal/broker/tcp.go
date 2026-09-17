// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"time"
)

// nowFunc is the wall clock for recording metadata; a var so tests can pin it.
var nowFunc = time.Now

// ProxyTCP dials targetAddr and proxies bytes bidirectionally with client until
// either side closes. Returns bytes copied client→target (up) and target→client
// (down). This is the raw-TCP brokering primitive used by jess-worker (5a).
func ProxyTCP(ctx context.Context, targetAddr string, client io.ReadWriteCloser) (up, down int64, err error) {
	tconn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return 0, 0, err
	}
	defer tconn.Close()

	done := make(chan struct{}, 2)
	go func() { up, _ = io.Copy(tconn, client); done <- struct{}{} }()
	go func() { down, _ = io.Copy(client, tconn); done <- struct{}{} }()

	<-done        // one direction ended
	tconn.Close() // unblock the other copy
	_ = client.Close()
	<-done
	return up, down, nil
}

func newSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "sess-" + hex.EncodeToString(b)
}
