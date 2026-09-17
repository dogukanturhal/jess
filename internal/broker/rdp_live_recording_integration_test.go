// SPDX-License-Identifier: AGPL-3.0-or-later

package broker

// ADR 0051 P4 — LIVE recording integration test against a real Windows DC.
//
// Gated OFF by default: it runs ONLY when JESS_RDP_LIVE=1 is set AND the live
// session_live binary + target creds are provided via env (the same env shape the
// jess-web bridge / engine read). It records a real brokered session into a v2
// WORM bundle and verifies the sealed bundle's frame/input counts + signature.
//
// Run:
//
//	JESS_RDP_LIVE=1 \
//	JESS_RDP_SESSION_BIN=services/ironrdp-broker/target/debug/session_live \
//	RDP_TARGET=10.0.20.10:3389 RDP_USER=jess-rdptest RDP_PASS='…' RDP_DOMAIN=HEXXLOCK \
//	go test ./internal/broker/ -run TestLiveRecordingAgainstRealDC -v -count=1 -timeout 120s

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dogukanturhal/jess/internal/catalog"
	"github.com/dogukanturhal/jess/internal/recording"
)

func TestLiveRecordingAgainstRealDC(t *testing.T) {
	if os.Getenv("JESS_RDP_LIVE") != "1" {
		t.Skip("set JESS_RDP_LIVE=1 (+ JESS_RDP_SESSION_BIN/RDP_TARGET/RDP_USER/RDP_PASS) for the live DC recording test")
	}
	bin := os.Getenv("JESS_RDP_SESSION_BIN")
	addr := os.Getenv("RDP_TARGET")
	user := os.Getenv("RDP_USER")
	pass := os.Getenv("RDP_PASS")
	if bin == "" || addr == "" || user == "" || pass == "" {
		t.Fatal("live test requires JESS_RDP_SESSION_BIN + RDP_TARGET + RDP_USER + RDP_PASS")
	}

	eng := newLiveRDPEngine(bin)
	dir := t.TempDir()
	store := recording.NewFSStore(dir)
	signer, err := recording.NewEd25519Signer("live-key")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	rec := recording.NewBundleRecorder(store, signer)

	const sid = "rdp-live-1"
	const subject = "live-operator@hexxlock"
	bw, err := rec.Open(context.Background(), recording.Meta{
		SessionID: sid, Subject: subject, TargetID: "win-dc-01", Protocol: "rdp", Format: recording.FormatRDPStreamV2,
	})
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	sw := recording.NewRDPStreamWriter(bw, recording.RDPStreamMeta{Subject: subject, Target: "win-dc-01", SessionID: sid})

	// A discard-on-read operator client: we drain server frames so the session
	// progresses, and never send input (a passive recording).
	client, _, outR := newOperatorBridge()
	target := &catalog.Target{ID: "win-dc-01", Protocol: catalog.ProtoRDP, Address: addr, Recorded: true}
	sec := RDPSecret{Kind: RDPSecretADCredential, Username: user, Password: pass, Domain: os.Getenv("RDP_DOMAIN")}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sess, err := eng.open(ctx, target, sec, client, ChannelPolicy{}, sw, RDPDesktopSize{})
	if err != nil {
		t.Fatalf("open live session: %v", err)
	}

	runDone := make(chan error, 1)
	go func() { runDone <- sess.Run() }()
	go io.Copy(io.Discard, outR) // drain server frames so the desktop keeps streaming

	// Record for ~8s of live desktop, then disconnect.
	time.Sleep(8 * time.Second)
	_ = client.Close()
	cancel()
	select {
	case <-runDone:
	case <-time.After(15 * time.Second):
		t.Log("Run did not return promptly after disconnect (continuing to seal)")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("seal bundle: %v", err)
	}

	// Verify + count.
	res, err := recording.VerifyDetail(context.Background(), store, sid, signer.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.SignatureValid || !res.HashMatch {
		t.Fatalf("LIVE bundle should verify: %+v", res)
	}
	content, _ := store.Get(context.Background(), res.Manifest.ContentKey)
	var resize, frames int
	for i, ln := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var ev struct{ Kind string }
		_ = json.Unmarshal([]byte(ln), &ev)
		if i == 0 {
			continue
		}
		switch ev.Kind {
		case "resize":
			resize++
		case "frame":
			frames++
		}
	}
	t.Logf("LIVE recording: subject=%s verify(sig=%v hash=%v) resize=%d frames=%d bytes=%d",
		res.Manifest.Subject, res.SignatureValid, res.HashMatch, resize, frames, res.Manifest.Bytes)
	if frames == 0 {
		t.Error("LIVE recording captured 0 frames — expected ≥1 decoded FRAME from a real desktop")
	}
}
