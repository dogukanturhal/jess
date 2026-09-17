// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Phase 7g — Attestation wiring.
//
// Builds the attestation.Registry from operator env config. Returns
// nil when no verifier is enabled — the attest handler is layered
// in unconditionally; without a registered verifier every attestation
// request is rejected with "no verifier registered".
//
// Operator env shape:
//
//   JESS_AWS_ATTESTATION=true            enable AWS Instance Identity Doc
//   JESS_AWS_ATTESTATION_KEYDIR=<path>   optional: directory of <region>.pub.pem
//                                         files (the AWS regional keys).
//                                         Without this, the AWS verifier
//                                         starts with an empty key map
//                                         (fail-closed on every request).
//   JESS_AWS_ATTESTATION_MAX_AGE=<dur>   document max-age (default 10m)
//
//   JESS_AZURE_ATTESTATION=true          enable Azure attested-data
//                                         (scaffold — Phase 7g-2)
//   JESS_AZURE_ATTESTATION_ROOTS=<path>  file holding Microsoft Azure
//                                         trust roots (PEM bundle).
//
// Wiring is intentionally fail-closed everywhere:
//   - No env set → no registry built → no /admin/attest acceptance
//   - Env set but key dir missing → verifier starts empty → fail-closed
//   - Env set + keys loaded → verifier accepts on signature match

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/dogukanturhal/jess/internal/attestation"
	awsverifier "github.com/dogukanturhal/jess/internal/attestation/aws"
	azureverifier "github.com/dogukanturhal/jess/internal/attestation/azure"
)

// buildAttestationRegistry constructs the verifier registry from
// env config. Returns nil when no provenance is enabled — caller
// MUST NOT pass nil to admin.NewAttest (the handler 503s gracefully
// on nil registry but the audit row would be uninformative).
func buildAttestationRegistry() *attestation.Registry {
	enabled := []string{}
	reg := attestation.NewRegistry()

	if os.Getenv("JESS_AWS_ATTESTATION") == "true" {
		v, err := awsverifier.New(durationFromEnv("JESS_AWS_ATTESTATION_MAX_AGE", 0))
		if err != nil {
			log.Fatalf("jess-controller: AWS attestation verifier init: %v", err)
		}
		// Optional: load operator-supplied region keys from a directory.
		if dir := os.Getenv("JESS_AWS_ATTESTATION_KEYDIR"); dir != "" {
			keys, err := loadAWSRegionalKeys(dir)
			if err != nil {
				log.Fatalf("jess-controller: AWS attestation keys from %s: %v", dir, err)
			}
			v.PubKeys = keys
			log.Printf("jess-controller: AWS attestation enabled with %d regional keys", len(keys))
		} else {
			log.Print("jess-controller: AWS attestation enabled WITHOUT keys (set JESS_AWS_ATTESTATION_KEYDIR to populate — every verify fails-closed until keys are present)")
		}
		reg.Register(v)
		enabled = append(enabled, "aws")
	}

	if os.Getenv("JESS_AZURE_ATTESTATION") == "true" {
		rootsPath := os.Getenv("JESS_AZURE_ATTESTATION_ROOTS")
		if rootsPath == "" {
			log.Fatal("jess-controller: JESS_AZURE_ATTESTATION=true requires JESS_AZURE_ATTESTATION_ROOTS (path to Azure root certs PEM)")
		}
		roots, err := os.ReadFile(rootsPath)
		if err != nil {
			log.Fatalf("jess-controller: read Azure roots %s: %v", rootsPath, err)
		}
		v, err := azureverifier.New(roots)
		if err != nil {
			log.Fatalf("jess-controller: Azure attestation verifier init: %v", err)
		}
		reg.Register(v)
		enabled = append(enabled, "azure")
	}

	if len(enabled) == 0 {
		return nil
	}
	log.Printf("jess-controller: attestation registry enabled with provenances=%v (Phase 7g)", enabled)
	return reg
}

// loadAWSRegionalKeys reads every *.pub.pem file in dir, treating the
// basename (minus .pub.pem) as the AWS region. e.g.
//
//	dir/us-east-1.pub.pem → keys["us-east-1"] = <RSA pub>
//	dir/eu-west-1.pub.pem → keys["eu-west-1"] = <RSA pub>
func loadAWSRegionalKeys(dir string) (map[string]*rsa.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("readdir: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".pub.pem") {
			continue
		}
		region := strings.TrimSuffix(name, ".pub.pem")
		pemBytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("%s: pem.Decode returned nil", name)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			// Fall back to PKCS#1 RSA format for older key dumps.
			rsaKey, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("%s: parse pub key: PKIX=%v / PKCS1=%v", name, err, err2)
			}
			out[region] = rsaKey
			continue
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: PKIX key is not RSA", name)
		}
		out[region] = rsaKey
	}
	return out, nil
}
