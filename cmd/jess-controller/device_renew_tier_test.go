// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"testing"

	"github.com/dogukanturhal/jess/internal/deviceattest"
	"github.com/dogukanturhal/jess/internal/devicecert"
)

type fakeCorpAsset struct {
	ok  bool
	err error
}

func (f fakeCorpAsset) IsCorporateAsset(context.Context, string) (bool, error) { return f.ok, f.err }

func idWithTier(tier string) *devicecert.Identity {
	c := &x509.Certificate{}
	if tier != "" {
		u, _ := url.Parse(devicecert.TierURIPrefix + tier)
		c.URIs = append(c.URIs, u)
	}
	return &devicecert.Identity{Leaf: c, DeviceUUID: "d1"}
}

func TestRenewalTier(t *testing.T) {
	rec := func(tier string) deviceattest.EnrolledDevice {
		return deviceattest.EnrolledDevice{DeviceUUID: "d1", Tier: tier, EKPubkeyHash: "ek"}
	}
	cases := []struct {
		name      string
		presented string
		dev       deviceattest.EnrolledDevice
		checker   CorpAssetChecker
		enforce   bool
		want      string
	}{
		{"corp kept when still corp asset", "TIER_CORP", rec("TIER_BYOD"), fakeCorpAsset{ok: true}, true, "TIER_CORP"},
		{"corp downgraded when asset removed (enforce)", "TIER_CORP", rec("TIER_BYOD"), fakeCorpAsset{ok: false}, true, "TIER_BYOD"},
		{"corp kept in audit mode", "TIER_CORP", rec("TIER_BYOD"), fakeCorpAsset{ok: false}, false, "TIER_CORP"},
		{"corp kept on allowlist error", "TIER_CORP", rec("TIER_BYOD"), fakeCorpAsset{err: errors.New("blip")}, true, "TIER_CORP"},
		{"record CORP alone is not trusted", "", rec("TIER_CORP"), fakeCorpAsset{ok: true}, true, "TIER_BYOD"},
		{"byod record, no presented tier", "", rec("TIER_BYOD"), nil, true, "TIER_BYOD"},
		{"no record: carry presented tier", "TIER_CORP", deviceattest.EnrolledDevice{}, fakeCorpAsset{ok: false}, true, "TIER_CORP"},
		{"no record, no presented tier", "", deviceattest.EnrolledDevice{}, nil, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &DeviceRenewHandler{corpAsset: tc.checker, corpAssetEnforce: tc.enforce}
			if got := h.renewalTier(context.Background(), idWithTier(tc.presented), tc.dev); got != tc.want {
				t.Errorf("renewalTier=%q want %q", got, tc.want)
			}
		})
	}
}
