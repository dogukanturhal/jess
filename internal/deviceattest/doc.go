// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deviceattest verifies end-user device hardware attestation
// evidence as the basis for issuing ZTNA device certificates per
// Talon ADR 0040 Phase 3 and jess ADR 0043.
//
// Why this is separate from internal/attestation
// ===============================================
// internal/attestation/ (Phase 7g) handles CLOUD HOST attestation:
// AWS EC2 Instance Identity Documents and Azure VM attested-data — its
// Provenance taxonomy is cloud accounts; its trust model chains to
// AWS/Azure/GCP region keys.
//
// deviceattest (Phase 3) handles END-USER DEVICE attestation: "this
// laptop claims to have a TPM-bound key — prove the hardware rooted
// it." The taxonomy is hardware platform (TPM 2.0, Apple SE, Android
// StrongBox, macOS MDM); the trust model chains to TPM-vendor /
// device-OEM root CAs or falls back to trust-on-first-use (TOFU).
//
// Conflating these would force one Provenance enum to mix "aws" with
// "tpm2-linux" and one Document shape to carry both InstanceID and
// device_uuid — readers would have to constantly check which axis is
// load-bearing. Separate package, separate interface.
//
// Path A vs Path B (ADR 0043 §3.c.0)
// ====================================
// Live verification on the jess maintainer workstation (2026-06-06)
// revealed that AMD consumer Ryzen fTPM does not provision an EK
// certificate:
//
//	TPM2_PT_MANUFACTURER = 0x414D4400 ("AMD")
//	driver = tpm_crb (CRB firmware TPM)
//	NV 0x01C00002 (RSA EK cert) → Esys_NV_ReadPublic failed
//	NV 0x01C0000A (ECC EK cert) → Esys_NV_ReadPublic failed
//
// The EK key IS hardware-rooted (PSP-fuse-derived, unique per CPU),
// but the manufacturer cert chain to an AMD root CA is absent. This
// is a documented industry gap — Microsoft Intune, IBM ACS, and
// tpm2-pkcs11 all handle it via TOFU.
//
// Exception: AMD Ryzen Pro + Microsoft Pluton SKUs DO ship an EK cert
// chained to Microsoft TPM Root CA 2014/2018. Those report
// MANUFACTURER=MSFT (not AMD), so an AMD-string TPM is consumer fTPM
// by definition.
//
// Two trust paths:
//
//	Path A (A_chain): EK cert chain to pinned manufacturer root CA.
//	  Discrete TPMs (Infineon, Nuvoton, STMicro, NationZ), Intel PTT,
//	  AMD Ryzen Pro + Pluton (MANUFACTURER=MSFT). Trust ceiling: TIER_CORP.
//
//	Path B (B_tofu): EK pubkey trust-on-first-use + operator
//	  WebAuthn-signed enrollment witness. AMD consumer fTPM and other
//	  unprovisioned TPMs. Trust ceiling: TIER_BYOD per ADR 0040 D-006.
//	  Talon Rego (Phase 5 baseline) gates on tier, so Path B devices
//	  automatically exit high-sensitivity routes without verifier-side
//	  custom logic.
//
// Anti-spoof rule: RequiresTOFU(manufacturer, kind) is a controller-
// side guard. Even if a client asserts ek_cert_present=true, the
// controller independently classifies the manufacturer before routing
// to Path A — this prevents a compromised agent from claiming a cert
// exists when it does not.
//
// Verifier layout (ADR 0043 §3.c)
// =================================
// This package exposes the Verifier interface, VerifyRequest/Response
// shapes, WitnessBundle, EnrollmentStore, WitnessVerifier, and a
// Registry dispatcher. Concrete implementations:
//
//   - tofuVerifier — Path B: EK pubkey TOFU + WebAuthn witness
//   - chainVerifier — Path A: EK cert chain to pinned vendor root
//
// The tier_matrix.go RequiresTOFU function encodes the manufacturer+kind
// → path routing decision table.
package deviceattest
