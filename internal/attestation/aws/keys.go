// SPDX-License-Identifier: AGPL-3.0-or-later

package aws

// AWS region → PEM-encoded RSA public key.
//
// AWS publishes the regional public keys for Instance Identity
// Document signatures at:
//
//	https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
//
// We INTENTIONALLY do NOT compile keys into the binary. Reasons:
//
//  1. Source-of-truth fidelity: AWS rotates these keys; embedding
//     them in jess means every rotation requires a release of the
//     entire jess binary. Operators with their own provisioning
//     pipeline should be able to update keys without a jess release.
//
//  2. Honesty: we're not in a position to vouch for which keys are
//     current at every region. The operator deploying jess into a
//     particular region SHOULD fetch the key from AWS docs at deploy
//     time and feed it to the verifier explicitly — that's the same
//     trust model Teleport, Boundary, and SSM use.
//
// Operator workflow (one-time per region):
//
//  1. Visit the AWS docs page above; copy the cert PEM for your
//     region.
//  2. Extract the public key:
//     openssl x509 -in cert.pem -pubkey -noout > us-east-1.pub.pem
//  3. Mount the PEM into the jess-controller pod at
//     /etc/jess/aws-keys/<region>.pub.pem
//  4. Set JESS_AWS_ATTESTATION_KEYDIR=/etc/jess/aws-keys on the
//     controller; main.go will load every <region>.pub.pem entry at
//     startup.
//
// The map below is intentionally empty so the binary fails-closed if
// nothing's provided — better than silently accepting documents from
// a region the operator forgot to wire keys for.
var embeddedKeys = map[string]string{}
