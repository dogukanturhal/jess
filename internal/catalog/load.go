// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFile reads a JSON array of Target from path (used by the controller +
// worker mains to seed the catalog). In later phases this is a CRD/DB source.
func LoadFile(path string) ([]*Target, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets %s: %w", path, err)
	}
	var ts []*Target
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, fmt.Errorf("parse targets %s: %w", path, err)
	}
	return ts, nil
}
