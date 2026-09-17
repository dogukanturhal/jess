// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// offline_creds_wiring — DDIL P3.8 construction of the pre-positioned
// offline-credentials manager for the live RDP console. OFF by default; enabled
// with JESS_OFFLINE_CREDS_ENABLED=1. When on, it wraps the Vault RDP credential
// broker so an eligible (opted-in, non-Tier-0) target survives a Vault outage on
// a governed short-TTL cached credential, and starts the background
// pre-position/refresh loop bound to the process lifetime.

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dogukanturhal/jess/internal/broker"
	"github.com/dogukanturhal/jess/internal/offlinecreds"
	"github.com/dogukanturhal/jess/internal/vaultx"
)

// offlineCredsEnabled reports whether the P3.8 pre-positioned offline-credential
// path is switched on. Default OFF (secure default: a Vault outage halts new
// privileged sessions, as today, until an operator opts in per target AND flips
// this master switch).
func offlineCredsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("JESS_OFFLINE_CREDS_ENABLED"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// newOfflineRDPCreds builds the offline-credentials manager over the Vault RDP
// mint (vb) + Vault client (vc for lease revoke), starts its refresh loop under
// ctx, and returns the wrapping credential broker. Config (all with documented
// defaults):
//
//	JESS_OFFLINE_CREDS_ENABLED           master switch                    (default off)
//	JESS_OFFLINE_CREDS_MAX_TTL           global cap on per-target MaxTTL   (default 4h)
//	JESS_OFFLINE_CREDS_MAX_USES          global cap on per-target MaxUses  (default 3)
//	JESS_OFFLINE_CREDS_REFRESH_INTERVAL  pre-position refresh tick         (default 60s)
//	JESS_OFFLINE_CREDS_SEAL_KEY          base64 32-byte at-rest seal key   (default ephemeral in-memory)
//	JESS_OFFLINE_CREDS_TIER0_DENY        extra target IDs pinned out       (default none; criticality=critical always excluded)
func newOfflineRDPCreds(ctx context.Context, vb broker.RDPCredBrokerWithPreposition, vc *vaultx.Client) (*broker.OfflineRDPCredBroker, error) {
	caps := offlinecreds.Caps{
		MaxTTL:  durationEnv("JESS_OFFLINE_CREDS_MAX_TTL", offlinecreds.DefaultMaxTTL),
		MaxUses: intEnv("JESS_OFFLINE_CREDS_MAX_USES", offlinecreds.DefaultMaxUses),
	}
	refresh := durationEnv("JESS_OFFLINE_CREDS_REFRESH_INTERVAL", 60*time.Second)

	// At-rest sealer: an operator-provided 32-byte key makes the sealed cache
	// portable/durable; the secure default is an ephemeral per-process key.
	var sealer *offlinecreds.Sealer
	if raw := strings.TrimSpace(os.Getenv("JESS_OFFLINE_CREDS_SEAL_KEY")); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("JESS_OFFLINE_CREDS_SEAL_KEY: base64 decode: %w", err)
		}
		s, err := offlinecreds.NewSealer(key)
		if err != nil {
			return nil, err
		}
		sealer = s
		log.Print("jess-web RDP live: offline creds at-rest seal key = configured (JESS_OFFLINE_CREDS_SEAL_KEY)")
	} else {
		log.Print("jess-web RDP live: offline creds at-rest seal key = ephemeral in-memory (default)")
	}

	guard := offlinecreds.NewTier0Guard(splitCSV(os.Getenv("JESS_OFFLINE_CREDS_TIER0_DENY")))

	// The Vault RDP broker is BOTH the pre-position minter (IssueForPreposition)
	// and the online per-session mint (IssueForOperator). vc backs emergency
	// lease revoke on reconnect.
	mgr, err := offlinecreds.New(offlinecreds.Config{
		Minter:          broker.NewRDPOfflineMinter(vb),
		Revoker:         broker.NewVaultLeaseRevoker(vc),
		Sealer:          sealer,
		Guard:           guard,
		Caps:            caps,
		RefreshInterval: refresh,
	})
	if err != nil {
		return nil, err
	}
	go mgr.Run(ctx)

	wrapped, err := broker.NewOfflineRDPCredBroker(vb, mgr)
	if err != nil {
		return nil, err
	}
	log.Printf("jess-web RDP live: DDIL P3.8 pre-positioned offline credentials ENABLED (max_ttl<=%s max_uses<=%d refresh=%s) — opt-in per target, Tier-0 (criticality=critical) hard-excluded",
		caps.MaxTTL, caps.MaxUses, refresh)
	return wrapped, nil
}

// splitCSV parses a comma-separated env value into trimmed non-empty items.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
