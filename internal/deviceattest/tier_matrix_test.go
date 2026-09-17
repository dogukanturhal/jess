// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

import "testing"

func TestRequiresTOFU(t *testing.T) {
	// Decision table from tier_matrix.go + ADR 0043 §3.c.0.
	// Changes to this table propagate to path-routing and audit rows
	// cluster-wide — any drift must be intentional and reviewed.
	cases := []struct {
		name         string
		manufacturer string
		kind         string
		want         bool
	}{
		// The canonical Path B case: live-verified on jess maintainer
		// workstation 2026-06-06 (TPM2_PT_MANUFACTURER = 0x414D4400,
		// driver = tpm_crb, NV 0x01C00002 + 0x01C0000A both TPM Error).
		{
			name:         "amd_consumer_firmware_tpm_is_tofu",
			manufacturer: "AMD",
			kind:         "firmware",
			want:         true,
		},
		// AMD Ryzen Pro + Pluton reports MANUFACTURER=MSFT, not AMD.
		// An AMD-string manufacturer + pluton kind is hypothetically
		// impossible in real hardware but must default false.
		{
			name:         "amd_pluton_kind_is_not_tofu",
			manufacturer: "AMD",
			kind:         "pluton",
			want:         false,
		},
		// AMD + discrete: AMD does not produce a discrete TPM; this
		// combination is hypothetically a third-party claim. Default false.
		{
			name:         "amd_discrete_is_not_tofu",
			manufacturer: "AMD",
			kind:         "discrete",
			want:         false,
		},
		// Microsoft Pluton (incl AMD Ryzen Pro path via MANUFACTURER=MSFT).
		// Chains to MS TPM Root CA 2014/2018 — Path A eligible.
		{
			name:         "msft_pluton_is_not_tofu",
			manufacturer: "MSFT",
			kind:         "pluton",
			want:         false,
		},
		{
			name:         "msft_firmware_is_not_tofu",
			manufacturer: "MSFT",
			kind:         "firmware",
			want:         false,
		},
		// Intel PTT provisions EK cert via Intel On-Die CA.
		{
			name:         "intel_firmware_ptt_is_not_tofu",
			manufacturer: "INTC",
			kind:         "firmware",
			want:         false,
		},
		// Discrete TPMs all provision EK certs from manufacturer CAs.
		{
			name:         "infineon_discrete_is_not_tofu",
			manufacturer: "IFX",
			kind:         "discrete",
			want:         false,
		},
		{
			name:         "nuvoton_discrete_is_not_tofu",
			manufacturer: "NTC",
			kind:         "discrete",
			want:         false,
		},
		{
			name:         "stmicro_discrete_is_not_tofu",
			manufacturer: "STM",
			kind:         "discrete",
			want:         false,
		},
		{
			name:         "nationz_discrete_is_not_tofu",
			manufacturer: "NZ",
			kind:         "discrete",
			want:         false,
		},
		// Unknown manufacturer: default safe (rejected by chain verify;
		// operator must explicitly add to TOFU allowlist).
		{
			name:         "unknown_manufacturer_is_not_tofu",
			manufacturer: "",
			kind:         "",
			want:         false,
		},
		{
			name:         "garbage_manufacturer_is_not_tofu",
			manufacturer: "XYZQ",
			kind:         "firmware",
			want:         false,
		},
		// Known-bad combo: kind=firmware without matching manufacturer.
		{
			name:         "non_amd_firmware_with_firmware_kind_is_not_tofu",
			manufacturer: "IFX",
			kind:         "firmware",
			want:         false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RequiresTOFU(tc.manufacturer, tc.kind)
			if got != tc.want {
				t.Errorf("RequiresTOFU(%q, %q) = %v, want %v",
					tc.manufacturer, tc.kind, got, tc.want)
			}
		})
	}
}
