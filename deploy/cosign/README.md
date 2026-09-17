# Jess cosign signing key

Per-repo cosign keypair for the Jess supply-chain pipeline (ADR 0030 Phase 5),
mirroring the talon / falcon-id pattern (each product owns a dedicated key).

- `cosign.pub` — the **public** verification key, committed here. The CI
  `verify:jess` stage verifies the freshly-signed image + SLSA provenance
  attestation against it before the image is considered releasable.
- The **private** key never lives in git. Sources of truth:
  - Vault: `example/platform/prod/jess/cosign` → `key` (encrypted PEM),
    `pub`, `password`.
  - GitLab CI variables on the `jess` project (protected, master-only):
    `COSIGN_PRIVATE_KEY` (file-type, the encrypted PEM) and `COSIGN_PASSWORD`.
  - Operator break-glass mirror: `SECRETS.local.txt` (`JESS_COSIGN_*`).

## Pipeline

`build:jess → sign:jess (cosign sign + slsaprovenance1 attest) → scan:jess
(Harbor Trivy gate, HIGH+CRITICAL ≤ HARBOR_VULN_THRESHOLD) → verify:jess
(cosign verify signature + attestation)`. Scanner outputs (SBOM + Trivy) are
pushed to DefectDojo (`report:defectdojo`).

## Rotation

The CA is **not** rotated by CI. To rotate:

1. `COSIGN_PASSWORD=<new> cosign generate-key-pair`
2. Update Vault `example/platform/prod/jess/cosign` + the two GitLab CI vars.
3. Replace `cosign.pub` here and commit.
4. Previously-signed images stay verifiable only against the OLD pub — keep an
   archived copy if you must verify historical images.
