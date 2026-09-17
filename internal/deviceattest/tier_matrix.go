// SPDX-License-Identifier: AGPL-3.0-or-later

package deviceattest

// RequiresTOFU returns true when the manufacturer + kind combination is
// known to ship WITHOUT a provisioned EK certificate (Path B required).
//
// This is a controller-side anti-spoof guard — even if the client agent
// asserts ek_cert_present=true, the controller MUST independently probe
// and classify before routing to Path A. A compromised agent could claim
// a cert is present when the TPM hardware does not have one.
//
// Decision table (ADR 0043 §3.c.0, verified 2026-06-06):
//
//	Manufacturer   Kind        RequiresTOFU   Rationale
//	------------   --------    ------------   ---------
//	AMD            firmware    true           Consumer Ryzen fTPM: PSP-fuse
//	                                          EK key but no EK cert in NV
//	                                          0x01C00002 / 0x01C0000A
//	                                          (live-verified on maintainer
//	                                          workstation 2026-06-06)
//	AMD            discrete    false          Hypothetical — AMD does not
//	                                          produce a discrete TPM; treat
//	                                          as Path A eligible
//	AMD            pluton      false          AMD Ryzen Pro + Pluton reports
//	                                          MANUFACTURER=MSFT not AMD; this
//	                                          branch is unreachable in practice
//	MSFT           *           false          Microsoft Pluton chains to
//	                                          MS TPM Root CA 2014/2018
//	INTC           firmware    false          Intel PTT provisions EK cert
//	                                          via Intel On-Die CA
//	IFX            discrete    false          Infineon Optiga discrete TPM
//	                                          chains to Infineon root
//	NTC            discrete    false          Nuvoton NPCT discrete TPM
//	NZ             discrete    false          NationZ Z32 discrete TPM
//	STM            discrete    false          STMicro ST33 discrete TPM
//	(unknown)      *           false          Default safe: unknown hardware
//	                                          is rejected by chain verify;
//	                                          operator must explicitly
//	                                          add to TOFU allowlist
func RequiresTOFU(manufacturer, kind string) bool {
	return manufacturer == "AMD" && kind == "firmware"
}
