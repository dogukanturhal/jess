// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestExtractPositional(t *testing.T) {
	mkFS := func() *flag.FlagSet {
		fs := flag.NewFlagSet("connect", flag.ContinueOnError)
		fs.String("controller", "", "")
		fs.String("grant", "", "")
		fs.String("listen", "", "")
		fs.Bool("tls", false, "")
		fs.String("tls-ca", "", "")
		return fs
	}
	tests := []struct {
		name     string
		args     []string
		wantPos  string
		wantRest []string
	}{
		{
			name:     "target last",
			args:     []string{"--controller", "x:1", "--grant", "g", "target"},
			wantPos:  "target",
			wantRest: []string{"--controller", "x:1", "--grant", "g"},
		},
		{
			name:     "target first",
			args:     []string{"target", "--controller", "x:1", "--grant", "g"},
			wantPos:  "target",
			wantRest: []string{"--controller", "x:1", "--grant", "g"},
		},
		{
			name:     "target in middle",
			args:     []string{"--controller", "x:1", "target", "--grant", "g"},
			wantPos:  "target",
			wantRest: []string{"--controller", "x:1", "--grant", "g"},
		},
		{
			name:     "bool flag in front of target",
			args:     []string{"--tls", "target", "--controller", "x:1", "--grant", "g"},
			wantPos:  "target",
			wantRest: []string{"--tls", "--controller", "x:1", "--grant", "g"},
		},
		{
			name:     "--flag=value form",
			args:     []string{"--controller=x:1", "target", "--grant=g"},
			wantPos:  "target",
			wantRest: []string{"--controller=x:1", "--grant=g"},
		},
		{
			name:     "two positionals — second passes through",
			args:     []string{"target", "extra", "--controller", "x:1"},
			wantPos:  "target",
			wantRest: []string{"extra", "--controller", "x:1"},
		},
		{
			name:     "-- stops scan",
			args:     []string{"--controller", "x:1", "--", "--target"},
			wantPos:  "",
			wantRest: []string{"--controller", "x:1", "--", "--target"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := mkFS()
			rest, pos := extractPositional(fs, tc.args)
			if pos != tc.wantPos {
				t.Errorf("pos = %q, want %q", pos, tc.wantPos)
			}
			if !reflect.DeepEqual(rest, tc.wantRest) {
				t.Errorf("rest = %v, want %v", rest, tc.wantRest)
			}
			if err := fs.Parse(rest); err != nil {
				t.Errorf("Parse(rest) error: %v", err)
			}
		})
	}
}
