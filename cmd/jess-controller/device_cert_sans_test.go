// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"reflect"
	"testing"

	"github.com/dogukanturhal/jess/internal/devicecert"
)

func TestDeviceCertURISans(t *testing.T) {
	const uuid = "76580a54-0000-4000-8000-000000000001"
	spiffe := devicecert.SPIFFEPrefix + uuid
	cases := []struct {
		name, tier string
		want       []string
	}{
		{"corp", "TIER_CORP", []string{spiffe, "urn:hexxlock:device-tier:TIER_CORP"}},
		{"byod", "TIER_BYOD", []string{spiffe, "urn:hexxlock:device-tier:TIER_BYOD"}},
		{"empty omits tier", "", []string{spiffe}},
		{"unknown omits tier", "TIER_ROOT", []string{spiffe}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deviceCertURISans(uuid, tc.tier); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("deviceCertURISans(%q)=%v want %v", tc.tier, got, tc.want)
			}
		})
	}
}
