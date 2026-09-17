// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wire holds the on-the-wire protocol types shared between the Jess
// controller and operator clients (jessctl), so the request format has a single
// source of truth.
package wire

// OperatorRequest is sent by an operator client to the controller's operator
// port as a single JSON object, immediately followed by the raw session bytes.
// Subject is NOT included — the controller derives the identity from the
// verified Token, so a client cannot impersonate another user.
type OperatorRequest struct {
	Token    string `json:"token"`
	TargetID string `json:"target_id"`
	GrantID  string `json:"grant_id"`
}
